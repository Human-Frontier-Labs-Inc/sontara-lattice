# Playbook: Tailscale Control Plane Outage

Tailscale is the network fabric for the entire Sontara Lattice fleet. All inter-machine communication -- broker API, NATS events, SSH, Syncthing, gridwatch -- flows over Tailscale's WireGuard mesh. If the Tailscale control plane goes down, existing connections persist but new connections fail, MagicDNS stops resolving, and any machine that restarts loses mesh connectivity until the control plane recovers.

## Architecture (What Makes This Dangerous)

```
Tailscale dependency map:

  Control Plane (external, login.tailscale.com):
    - Key exchange for new/restarted connections
    - MagicDNS resolution
    - ACL distribution
    - DERP relay coordination
    - Device authentication

  What uses Tailscale IPs directly (survives outage):
    - broker_url: http://<broker-ip>:7899
    - nats_url: nats://<broker-ip>:4222
    - LiteLLM: http://<broker-ip>:4000
    - NATS monitor: http://<broker-ip>:8222
    - SSH: configured with Tailscale IPs in ~/.ssh/config (mostly)
    - Gridwatch: http://<broker-ip>:8888

  What uses MagicDNS hostnames (BREAKS during outage):
    - SSH config entries using hostnames: "broker-server", "edge-node", etc.
    - Syncthing device connections (may use hostname discovery)
    - Any script/config using MagicDNS names instead of IPs

  DERP relay (for NAT traversal):
    - Machines behind NAT (iot-device on 4G, laptop-1 on wifi)
    - If direct WireGuard tunnel exists, DERP not needed
    - If DERP relay is needed and control plane is down, new relay paths fail

Fleet Tailscale IPs (hardcoded fallbacks):
  workstation:        <workstation-ip>
  broker-server: <broker-ip>
  workstation-2:      <workstation-2-ip>
  laptop-1:       <laptop-1-ip>
  iot-device:        <iot-device-ip>
  laptop-2:     <laptop-2-ip>
  edge-node:       (check tailscale status for current IP)
```

### Key Behavior During Control Plane Outage

1. **Existing WireGuard tunnels persist.** If two machines already have a direct WireGuard tunnel established, they continue communicating. The tunnel uses pre-exchanged keys that don't need the control plane.

2. **New connections fail.** If a machine has never connected to another machine (or the tunnel expired), the key exchange requires the control plane. These connections will not establish.

3. **Machine restarts are fatal.** If a machine reboots during the outage, its Tailscale daemon restarts and tries to reach the control plane to re-authenticate. This fails, and the machine drops off the mesh entirely.

4. **MagicDNS stops resolving.** Any DNS lookup for `<hostname>.tailnet-name.ts.net` or shortnames like `broker-server` fails. Hardcoded Tailscale IPs still work.

5. **DERP relay paths degrade.** New relay paths cannot be negotiated. Machines that depend on DERP (behind strict NAT) may lose connectivity even if the control plane comes back, until they can re-negotiate.

## Detection

### Check Tailscale Status

```bash
# On any fleet machine
tailscale status

# Look for:
# - "Tailscale is stopped" (daemon down)
# - Peers showing as "idle" or missing
# - Self showing "offline"
# - Network error messages
```

### Check Tailscale Health

```bash
tailscale netcheck

# Look for:
# - "control plane: unreachable"
# - DERP regions showing as unavailable
# - High latency to DERP servers
```

### Check DNS Resolution

```bash
# Test MagicDNS
nslookup broker-server 2>/dev/null || echo "MagicDNS FAILED"

# Test direct IP connectivity
ping -c 1 -W 3 <broker-ip> && echo "Direct IP OK" || echo "Direct IP FAILED"
```

### Check Tailscale Status Page

```bash
echo "https://tailscale.com/status"
echo "https://status.tailscale.com"
```

### Fleet-Wide Connectivity Check

```bash
echo "=== Fleet Connectivity Check (using direct IPs) ==="
for entry in "workstation:<workstation-ip>" "broker-server:<broker-ip>" "workstation-2:<workstation-2-ip>" "laptop-1:<laptop-1-ip>" "iot-device:<iot-device-ip>" "laptop-2:<laptop-2-ip>"; do
  name="${entry%%:*}"
  ip="${entry##*:}"
  if ping -c 1 -W 3 "$ip" >/dev/null 2>&1; then
    echo "  $name ($ip): REACHABLE"
  else
    echo "  $name ($ip): UNREACHABLE"
  fi
done
```

### GAP: No Tailscale Health Monitoring

There is currently **no automated monitoring** of Tailscale connectivity health. No daemon checks `tailscale status` periodically, no alerts fire when the control plane is unreachable, and no NATS event is published when tailscale health degrades.

**STATUS: NOT IMPLEMENTED**

## Impact Assessment

### What Continues Working

If all machines are currently connected and nobody reboots:

- Broker API at <broker-ip>:7899 (uses Tailscale IP directly)
- NATS at <broker-ip>:4222 (uses Tailscale IP directly)
- All NATS subscribers and publishers (existing connections)
- SSH between machines with established tunnels
- Syncthing sync (established connections)
- Gridwatch dashboard
- All claude-peers services on broker-server (localhost communication)
- Daemon invocations (supervisor is local to broker-server)

### What Breaks

- SSH to machines using hostname-based config (MagicDNS lookup fails)
- New connections between machines that haven't communicated recently
- Any machine that reboots during the outage
- fleet-scout SSH checks to machines (if using MagicDNS hostnames)
- Syncthing discovery of new peers
- Adding new devices to the fleet

### What Breaks If It Goes On Long Enough

- WireGuard key rotation (keys have a lifespan, typically hours)
- As keys expire, tunnels drop one by one
- Eventually all inter-machine connectivity is lost
- The fleet fragments into isolated machines

## Immediate Triage

### Step 1: Confirm it's a Tailscale outage (not a local issue)

```bash
# Check Tailscale daemon is running
systemctl is-active tailscaled

# Check if control plane is reachable
tailscale netcheck 2>&1 | head -20

# Check external status page
echo "Visit: https://status.tailscale.com"
```

### Step 2: Verify existing connections are stable

```bash
# Check which peers are currently connected
tailscale status | grep -v "^$"

# Test connectivity to critical infrastructure
ping -c 1 -W 3 <broker-ip> && echo "broker-server: OK" || echo "broker-server: DOWN"
curl -sf http://<broker-ip>:7899/health >/dev/null && echo "Broker: OK" || echo "Broker: DOWN"
```

### Step 3: DO NOT REBOOT ANY MACHINE

This is the most important rule during a Tailscale outage. Rebooting a machine drops its Tailscale tunnel and it cannot re-establish until the control plane is back.

**Especially do not reboot broker-server.** If broker-server loses its Tailscale connection, ALL fleet services become unreachable from other machines.

### Step 4: Switch to direct IPs for any hostname-based operations

```bash
# If you need to SSH to a machine and MagicDNS is down:
ssh user@<broker-ip>  # broker-server
ssh user@<workstation-ip>   # workstation
ssh user@<workstation-2-ip>    # workstation-2
ssh <user>@<laptop-1-ip><laptop-1-ip>  # laptop-1
ssh root@<iot-device-ip>       # iot-device
```

### Step 5: Monitor for recovery

```bash
# Poll Tailscale control plane status every 60 seconds
while true; do
  if tailscale netcheck 2>&1 | grep -q "no matching"; then
    echo "$(date): Control plane still down"
  else
    echo "$(date): Control plane may be recovering"
    tailscale netcheck
    break
  fi
  sleep 60
done
```

## Post-Recovery Verification

After the Tailscale control plane comes back:

### Step 1: Verify all machines reconnected

```bash
tailscale status

# All 7 machines should show as online
# If any are missing, they may need:
#   - tailscale up (if the daemon disconnected)
#   - A full machine reboot (if the daemon is in a bad state)
```

### Step 2: Re-establish any dropped connections

```bash
# SSH to each machine to force tunnel re-establishment
for ip in <broker-ip> <workstation-ip> <workstation-2-ip> <laptop-1-ip> <iot-device-ip> <laptop-2-ip>; do
  ssh -o ConnectTimeout=5 $ip "hostname" 2>/dev/null && echo "  $ip: OK" || echo "  $ip: FAILED"
done
```

### Step 3: Verify fleet services recovered

```bash
# Broker
curl -sf http://<broker-ip>:7899/health && echo "Broker: OK"

# NATS
nats stream info FLEET 2>/dev/null && echo "NATS: OK"

# Check peers re-registered
TOKEN=$(cat ~/.config/claude-peers/token.jwt)
curl -s -H "Authorization: Bearer $TOKEN" http://<broker-ip>:7899/peers | python3 -c "
import json, sys
peers = json.load(sys.stdin)
print(f'{len(peers)} peers registered')
"
```

### Step 4: Check if any machine rebooted during the outage

```bash
for entry in "broker-server:<broker-ip>" "workstation:<workstation-ip>" "edge-node:edge-node" "workstation-2:<workstation-2-ip>"; do
  name="${entry%%:*}"
  host="${entry##*:}"
  echo "=== $name ==="
  ssh -o ConnectTimeout=5 $host "uptime" 2>/dev/null || echo "  unreachable"
done
```

If a machine rebooted and is now unreachable, you may need to physically access it or wait for Tailscale to fully re-negotiate its tunnel.

## Decision Tree

```
Suspected Tailscale outage
|
+-- Can you reach the Tailscale control plane?
|   +-- NO (status.tailscale.com confirms outage)
|   |   +-- DO NOT REBOOT ANY MACHINE
|   |   +-- Verify existing tunnels are stable
|   |   +-- Switch to direct IPs for all operations
|   |   +-- Wait for recovery, monitor status page
|   |   +-- Post-recovery: verify all machines, run fleet connectivity check
|   |
|   +-- YES (control plane is up)
|       +-- Is it a local Tailscale issue?
|       |   +-- Check: systemctl is-active tailscaled
|       |   +-- Check: tailscale up
|       |   +-- Check: tailscale netcheck
|       |   +-- May need: sudo systemctl restart tailscaled
|       |
|       +-- Is it a network issue (not Tailscale)?
|           +-- Check ISP connectivity
|           +-- Check local router/firewall
|           +-- traceroute to Tailscale IP
|
+-- Has a machine rebooted during the outage?
|   +-- YES: Machine is likely offline until control plane recovers
|   |   +-- If critical (broker-server): attempt direct network access if available
|   |   +-- If non-critical: wait for recovery
|   |
|   +-- NO: All machines should maintain existing connections
|
+-- How long has the outage lasted?
    +-- < 1 hour: Low risk, existing tunnels fine
    +-- 1-6 hours: Medium risk, WireGuard keys may start expiring
    +-- > 6 hours: High risk, tunnels may drop as keys expire
        +-- Prepare for partial fleet fragmentation
        +-- Have direct IPs documented for manual SSH
```

## Monitoring Gaps Summary

| Gap | Severity | Status | Remediation |
|-----|----------|--------|-------------|
| No Tailscale health monitoring | **HIGH** | NOT IMPLEMENTED | Add a periodic check (`tailscale status --json`) as a fleet-scout check or standalone daemon |
| No alerting on control plane unreachable | **HIGH** | NOT IMPLEMENTED | Check `tailscale netcheck` periodically, publish alert to NATS or send email if control plane is down |
| Some configs use MagicDNS hostnames | **MEDIUM** | PARTIAL | Most configs use Tailscale IPs directly, but SSH config and some scripts may use hostnames |
| No documented IP fallback table | **LOW** | FIXED IN THIS PLAYBOOK | IP table documented above |
| No pre-outage key refresh | **LOW** | NOT FEASIBLE | WireGuard key rotation is handled by Tailscale automatically |

## Hardening Recommendations

1. **Use Tailscale IPs everywhere, never MagicDNS hostnames.** Audit all configs, scripts, and SSH config for hostname usage. Replace with direct IPs. The fleet already does this for broker_url and nats_url -- ensure consistency across all tools.

2. **Add Tailscale health monitoring.** A simple check in fleet-scout or as a standalone daemon:
   ```bash
   # Check Tailscale peer connectivity
   tailscale status --json | python3 -c "
   import json, sys
   data = json.load(sys.stdin)
   offline = [p['HostName'] for p in data.get('Peer', {}).values() if not p.get('Online')]
   if offline:
       print(f'OFFLINE peers: {offline}')
   "
   ```

3. **Document the "no reboot" rule.** During any network outage, rebooting is the single worst thing you can do. This should be in fleet runbooks, and ideally the gridwatch dashboard should show a banner when Tailscale control plane issues are detected.

4. **Keep SSH config entries with both hostname and IP.** In `~/.ssh/config`, use `HostName 100.x.x.x` with direct IPs rather than relying on MagicDNS resolution.

5. **Consider Headscale as a self-hosted fallback.** Headscale is an open-source Tailscale control plane. Running it on broker-server would provide control plane independence, but adds operational complexity and doesn't help if broker-server itself is down.
