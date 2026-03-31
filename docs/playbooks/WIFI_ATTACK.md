# WiFi Attack Incident Response Playbook

Sontara Lattice fleet -- last updated 2026-03-28.

**Tier:** 2 (Contain) -- WiFi attacks can intercept non-mesh traffic and potentially compromise device credentials on public networks.

**Current Detection: NONE** -- No WiFi security monitoring on any fleet machine. No rogue AP detection, no ARP monitoring, no certificate validation alerts.

**Machines at risk:**
| Machine | WiFi Usage | Risk Level | Tailscale Exit Node |
|---------|-----------|-----------|-------------------|
| iot-device | Always on WiFi -- connects to hotspots, public networks | HIGH | Not configured |
| laptop-1 | Cafe WiFi, home WiFi | HIGH | Not configured |
| workstation-2 | Cafe WiFi, home WiFi | MEDIUM | Not configured |
| workstation | Home WiFi only | LOW | Not configured |
| edge-node | Home WiFi only | LOW | Not configured |
| broker-server | Wired Ethernet | NONE | Could serve as exit node |

---

## Attack Surface

### What Tailscale protects

All fleet mesh traffic (broker API, NATS, SSH between machines, peer messages) goes through Tailscale WireGuard tunnels. This traffic is:
- End-to-end encrypted (WireGuard)
- Authenticated (Tailscale identity)
- Not visible to the WiFi network operator or MITM attacker

An attacker on the same WiFi network CANNOT:
- Read broker API requests/responses
- Inject NATS messages
- Intercept SSH sessions between fleet machines
- Impersonate a fleet machine

### What Tailscale does NOT protect

Traffic that leaves the machine for non-Tailscale destinations:

| Traffic Type | Protection | Risk |
|-------------|-----------|------|
| DNS queries | Cleartext (unless using Tailscale DNS or DoH) | Attacker sees all domains queried |
| apt/pacman updates | HTTP/HTTPS (repo signatures verify integrity) | Attacker sees update activity, potential downgrade attacks |
| NTP | Cleartext | Attacker can manipulate system time (affects UCAN token expiry, log correlation) |
| Web browsing | HTTPS (mostly) | Attacker sees SNI (which sites), can attempt SSL strip |
| Git clone/push over HTTPS | HTTPS | Attacker sees repo URLs |
| Syncthing discovery | Cleartext relay discovery | Attacker sees Syncthing is running |
| LiteLLM API calls to external providers | HTTPS | Attacker sees which LLM providers are called |

### Specific attack scenarios

**Evil twin WiFi for iot-device:**
iot-device connects to known WiFi networks automatically. An attacker sets up a WiFi AP with the same SSID and stronger signal. iot-device connects to the evil twin. The attacker can:
- See all non-Tailscale DNS queries (revealing fleet topology if any DNS lookups reference Tailscale hostnames)
- Serve malicious captive portal pages
- Intercept any non-HTTPS traffic
- Perform SSL stripping attacks on HTTP-to-HTTPS redirects
- Manipulate NTP responses to desync iot-device's clock

**Cafe MITM on laptop-1/workstation-2:**
On public WiFi (cafe, hotel, airport), the network operator or any attacker on the same network can:
- ARP poison to become the default gateway
- Intercept DNS and redirect to malicious servers
- Present fake certificate warnings (hoping the user clicks through)
- Capture any cleartext credentials (unlikely but possible with legacy services)

**NTP manipulation:**
UCAN tokens have expiry times. The token validation uses `time.Now()` with a 30-second leeway (see `ucan.go` line 132). If an attacker shifts the system clock forward via NTP manipulation, valid tokens could appear expired, causing a DoS. If shifted backward, expired tokens could appear valid.

**DNS hijacking on WiFi:**
If the attacker controls DNS responses, they can redirect any non-Tailscale hostname. This affects:
- `go.sum` verification (if GONOSUMCHECK is set, which it shouldn't be)
- Any external API calls from daemon runs
- Package manager updates (though signature verification provides a second layer)

---

## 1. Detection Signals

### Current state: NO automated detection

No WiFi security monitoring is configured. The following checks are all manual.

### Manual detection signals

**Unexpected network interfaces:**
```bash
ssh <machine> "ip addr show" 2>/dev/null || ssh <machine> "ifconfig"
# Look for interfaces you don't recognize (rogue VPN, extra bridges)
```

**ARP table anomalies:**
```bash
ssh <machine> "ip neigh show" 2>/dev/null || ssh <machine> "arp -a"
# Look for multiple MACs claiming to be the gateway
# Look for gateway MAC changes (ARP poisoning indicator)
```

**DNS resolution changes:**
```bash
ssh <machine> "cat /etc/resolv.conf"
ssh <machine> "resolvectl status 2>/dev/null" || ssh <machine> "systemd-resolve --status 2>/dev/null"
# Look for unexpected DNS servers
```

**Certificate warnings in logs:**
```bash
ssh <machine> "journalctl --since '24 hours ago' --no-pager | grep -iE 'certificate\|ssl\|tls\|x509'"
```

**Time drift (NTP manipulation indicator):**
```bash
# Compare time across fleet
for machine in <workstation-ip> <broker-ip> edge-node workstation-2-workstation "<user>@<laptop-1-ip><laptop-1-ip>" <iot-device-ip>; do
  echo -n "$machine: "
  ssh "$machine" "date -u +%Y-%m-%dT%H:%M:%S 2>/dev/null" 2>/dev/null || echo "unreachable"
done
# More than 5 seconds drift between machines is suspicious
```

**WiFi SSID check (is the machine connected to the right network?):**
```bash
# Linux
ssh <machine> "iwconfig 2>/dev/null | grep ESSID" || ssh <machine> "nmcli -t -f active,ssid dev wifi | grep '^yes'" 2>/dev/null

# macOS
ssh <machine> "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I | grep SSID"
```

---

## 2. Immediate Triage

If you suspect a WiFi-based attack (e.g., you're on public WiFi and notice strange behavior, DNS resolution failures, or certificate warnings):

### Step 1: Check the current WiFi connection

```bash
# Linux (iot-device, workstation-2, workstation)
ssh <machine> "nmcli dev wifi list 2>/dev/null"
# Look for multiple APs with the same SSID (evil twin indicator)
# Look for the currently connected AP's signal strength vs competitors

# macOS (laptop-1)
ssh <user>@<laptop-1-ip><laptop-1-ip> "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -s"
```

### Step 2: Verify Tailscale is up and routing correctly

```bash
ssh <machine> "tailscale status"
# All fleet machines should show as reachable
# If Tailscale shows "offline" for other machines, the WiFi might be blocking UDP (WireGuard)

ssh <machine> "tailscale ping <broker-ip>"
# Should show direct connection. If it shows relay, something is interfering.
```

### Step 3: Check for MITM indicators

```bash
# Check the ARP entry for the gateway
ssh <machine> "ip route show default"
# Note the gateway IP
ssh <machine> "ip neigh show <gateway-ip>"
# The MAC address should match the known router MAC

# Test DNS integrity
ssh <machine> "dig +short google.com @8.8.8.8"
ssh <machine> "dig +short google.com"
# If the results differ, DNS is being intercepted

# Test HTTPS certificate
ssh <machine> "openssl s_client -connect google.com:443 -servername google.com < /dev/null 2>/dev/null | openssl x509 -noout -issuer"
# Should show a Google/well-known CA issuer, not a self-signed or unknown CA
```

### Decision point

| Finding | Action |
|---------|--------|
| Multiple APs with same SSID, different MACs | Evil twin likely. Disconnect. Use cellular or Tailscale exit node. |
| Gateway MAC changed since last check | ARP poisoning. Disconnect WiFi. |
| DNS queries returning wrong IPs | DNS hijacking. Switch to Tailscale DNS or DoH. |
| Certificate issuer is unexpected/self-signed | Active MITM with SSL interception. Disconnect immediately. |
| Tailscale shows "relay" when it was previously "direct" | Network is blocking WireGuard UDP. May be benign (strict firewall) or malicious. |
| Time drift > 30 seconds on one machine | NTP manipulation. Fix time manually and investigate. |

---

## 3. Containment

### Disconnect from the untrusted WiFi

```bash
# Linux
ssh <machine> "nmcli dev disconnect wlan0" 2>/dev/null

# macOS
ssh <machine> "networksetup -setairportpower en0 off"

# iot-device (if unreachable via Tailscale, it's likely because WiFi is the only path)
# Physical access required -- press the WiFi toggle if available
```

### If the machine is unreachable

If the WiFi attack disrupted Tailscale connectivity (blocking WireGuard UDP):
- **iot-device:** Physical access required. It's a portable device -- locate it and disconnect WiFi
- **laptop-1/workstation-2:** Call the person using it and tell them to disconnect WiFi
- The machine is isolated from the fleet but potentially exposed to the attacker's network

### Enable Tailscale exit node for all traffic

This routes ALL traffic through Tailscale, including DNS and web browsing:

```bash
# On broker-server (the exit node):
ssh broker-server "sudo tailscale set --advertise-exit-node"

# On the machine using untrusted WiFi:
ssh <machine> "sudo tailscale set --exit-node=<broker-ip>"
```

After this, all traffic from the machine goes through the Tailscale tunnel to broker-server, then out to the internet from there. The WiFi network only sees encrypted WireGuard packets.

### Fix NTP if time was manipulated

```bash
# Set time manually
ssh <machine> "sudo timedatectl set-ntp false && sudo date -s '$(date -u +%Y-%m-%dT%H:%M:%SZ)' && sudo timedatectl set-ntp true"

# Or force NTP sync to a known good server
ssh <machine> "sudo ntpdate pool.ntp.org" 2>/dev/null || ssh <machine> "sudo chronyc makestep" 2>/dev/null
```

---

## 4. Investigation

### Determine what traffic was exposed

```bash
# Check if any non-HTTPS connections were made during the exposure window
ssh <machine> "journalctl --since '<start-time>' --until '<end-time>' --no-pager | grep -iE 'http://|ftp://'"

# Check for package manager activity during exposure
ssh <machine> "grep -E 'installed|upgraded' /var/log/pacman.log 2>/dev/null | tail -10"
ssh <machine> "grep -E 'install|upgrade' /var/log/apt/history.log 2>/dev/null | tail -10"

# Check if git operations happened over HTTPS (not SSH)
ssh <machine> "git -C ~/projects/claude-peers remote -v"
# If origin uses https://, git credentials may have been exposed
```

### Check for credential exposure

```bash
# Did any daemon make external API calls during the exposure?
ssh broker-server "journalctl --user -u claude-peers-supervisor --since '<start-time>' --until '<end-time>' --no-pager | grep -iE 'http\|api\|curl'"

# Check if browser sessions were active (laptop-1, workstation-2)
# Look for any "login" or "auth" URLs in browser history
```

### Check for persistent WiFi compromise

```bash
# Linux: check for rogue WiFi profiles
ssh <machine> "nmcli connection show 2>/dev/null"
# Look for connections you don't recognize

# Check for WiFi-related persistence
ssh <machine> "ls /etc/NetworkManager/system-connections/ 2>/dev/null"

# macOS: check known networks
ssh <machine> "networksetup -listpreferredwirelessnetworks en0"
```

---

## 5. Recovery

### Remove any rogue WiFi profiles

```bash
# Linux
ssh <machine> "nmcli connection delete '<rogue-ssid>'" 2>/dev/null

# macOS
ssh <machine> "networksetup -removepreferredwirelessnetwork en0 '<rogue-ssid>'"
```

### Reconnect to a trusted network

```bash
# Linux
ssh <machine> "nmcli dev wifi connect '<trusted-ssid>' password '<password>'" 2>/dev/null

# macOS
ssh <machine> "networksetup -setairportpower en0 on"
```

### Verify fleet connectivity

```bash
ssh <machine> "tailscale status"
ssh <machine> "claude-peers status"
```

---

## 6. Post-Incident Improvements

### Configure Tailscale exit node for portable devices

Set broker-server as an always-on exit node. Configure iot-device and laptop-1 to use it by default when on untrusted networks:

```bash
# On broker-server (one-time):
sudo tailscale set --advertise-exit-node

# On iot-device (permanent -- all traffic through Tailscale):
sudo tailscale set --exit-node=<broker-ip>

# On laptop-1/workstation-2 (when on untrusted WiFi):
sudo tailscale set --exit-node=<broker-ip>
```

### Configure Tailscale DNS

Use Tailscale's MagicDNS to handle DNS resolution through the Tailscale tunnel instead of the local WiFi's DNS:

```bash
# In Tailscale admin console:
# Enable MagicDNS
# Set global nameservers to trusted DNS (1.1.1.1, 8.8.8.8)
# Enable "Override local DNS"
```

### Harden NTP

Use authenticated NTP (NTS) or pin NTP to Tailscale-reachable servers:

```bash
# On all Linux machines, configure chrony or systemd-timesyncd to use NTS
# /etc/chrony.conf or /etc/systemd/timesyncd.conf
# Use NTS-capable servers: time.cloudflare.com
```

### WiFi hardening for iot-device

iot-device is the highest-risk device -- always on WiFi, portable, carried everywhere:

1. **Disable auto-connect to open networks**
2. **Remove all saved networks except trusted ones**
3. **Use Tailscale exit node by default** (all traffic encrypted)
4. **Disable WiFi power management** to prevent deauth attacks from causing reconnection to evil twins
5. **Consider 4G/LTE as primary** via the SIM7600 HAT (once configured) -- cellular is harder to MITM than WiFi

### Add WiFi monitoring script

Create a script that runs periodically and checks for WiFi anomalies:

```bash
#!/bin/bash
# /usr/local/bin/wifi-monitor.sh
# Run via cron or systemd timer every 5 minutes

GATEWAY=$(ip route show default | awk '{print $3}')
GATEWAY_MAC=$(ip neigh show $GATEWAY | awk '{print $5}')
EXPECTED_MAC_FILE=/etc/wifi-monitor/gateway-mac

if [ -f "$EXPECTED_MAC_FILE" ]; then
  EXPECTED_MAC=$(cat "$EXPECTED_MAC_FILE")
  if [ "$GATEWAY_MAC" != "$EXPECTED_MAC" ]; then
    logger -p auth.warn "WIFI-MONITOR: Gateway MAC changed from $EXPECTED_MAC to $GATEWAY_MAC (possible ARP poisoning)"
    # Publish to NATS if available
  fi
else
  echo "$GATEWAY_MAC" > "$EXPECTED_MAC_FILE"
fi

# Check for evil twin (multiple APs with same SSID)
CURRENT_SSID=$(nmcli -t -f active,ssid dev wifi | grep '^yes' | cut -d: -f2)
AP_COUNT=$(nmcli -t -f ssid dev wifi list | grep -c "^$CURRENT_SSID$")
if [ "$AP_COUNT" -gt 1 ]; then
  logger -p auth.warn "WIFI-MONITOR: Multiple APs with SSID '$CURRENT_SSID' detected (possible evil twin)"
fi
```

### Add time drift monitoring to fleet-scout

The fleet-scout daemon should compare system time across all machines on every health check. If any machine's clock drifts more than 5 seconds from the fleet median, flag it as a potential NTP manipulation attack.
