package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"
)

// runFleetDigest collects fleet status and sends an email digest.
// No LLM, no agent binary -- pure Go data collection + resend-email.
func runFleetDigest() {
	log.SetFlags(0)
	authToken = loadAuthToken()

	var b strings.Builder
	b.WriteString(fmt.Sprintf("SONTARA LATTICE - FLEET DIGEST\n%s\n\n", time.Now().Format("2006-01-02 15:04 MST")))

	// Broker status
	var health HealthResponse
	if err := cliFetch("/health", nil, &health); err == nil {
		b.WriteString(fmt.Sprintf("BROKER: %s | %d peers | machine: %s\n\n", health.Status, health.Peers, health.Machine))
	} else {
		b.WriteString(fmt.Sprintf("BROKER: unreachable (%v)\n\n", err))
	}

	// Active peers
	var peers []Peer
	if err := cliFetch("/list-peers", ListPeersRequest{Scope: "all", CWD: "/"}, &peers); err == nil && len(peers) > 0 {
		b.WriteString("ACTIVE SESSIONS\n")
		for _, p := range peers {
			name := p.Name
			if name == "" {
				name = p.Machine
			}
			summary := p.Summary
			if summary == "" {
				summary = "(no summary)"
			}
			b.WriteString(fmt.Sprintf("  %s: %s\n", name, summary))
		}
		b.WriteString("\n")
	}

	// Machine health
	var healthMap map[string]*MachineHealth
	if err := cliFetch("/machine-health", nil, &healthMap); err == nil && len(healthMap) > 0 {
		b.WriteString("SECURITY\n")
		anyIssues := false
		for machine, h := range healthMap {
			if h.Status != "healthy" {
				anyIssues = true
				b.WriteString(fmt.Sprintf("  !! %s: %s (score %d) -- %s\n", machine, h.Status, h.Score, h.LastEventDesc))
			}
		}
		if !anyIssues {
			b.WriteString(fmt.Sprintf("  All %d machines healthy\n", len(healthMap)))
		}
		b.WriteString("\n")
	}

	// Recent events
	var events []Event
	if resp, err := fetchEventsRaw(); err == nil && len(resp) > 0 {
		events = resp
		b.WriteString("RECENT EVENTS (last 20)\n")
		shown := 0
		for _, e := range events {
			if shown >= 10 {
				break
			}
			// Skip noisy summary_changed events (frequent updates)
			if e.Type == "summary_changed" {
				continue
			}
			ago := ""
			if t, err := time.Parse(time.RFC3339, e.CreatedAt); err == nil {
				ago = time.Since(t).Truncate(time.Second).String()
			}
			data := e.Data
			if len(data) > 50 {
				data = data[:50] + "..."
			}
			b.WriteString(fmt.Sprintf("  %s %s %s %s\n", e.Type, e.Machine, data, ago))
			shown++
		}
		b.WriteString("\n")
	}

	// Daemon runs (from supervisor journal)
	daemonOut, err := exec.Command("bash", "-c",
		`journalctl --user -u claude-peers-supervisor --since "1 hour ago" --no-pager 2>/dev/null | grep -E "complete|failed" | tail -10`).Output()
	if err == nil && len(daemonOut) > 0 {
		b.WriteString("DAEMON RUNS (last hour)\n")
		for _, line := range strings.Split(strings.TrimSpace(string(daemonOut)), "\n") {
			// Extract daemon name and status
			parts := strings.Fields(line)
			if len(parts) >= 4 {
				// Find the [supervisor] daemon: part
				for i, p := range parts {
					if strings.HasPrefix(p, "[supervisor]") && i+1 < len(parts) {
						b.WriteString(fmt.Sprintf("  %s\n", strings.Join(parts[i:], " ")))
						break
					}
				}
			}
		}
		b.WriteString("\n")
	}

	// Open PRs
	prOut, _ := exec.Command("gh", "pr", "list", "--repo", "Human-Frontier-Labs-Inc/sontara-lattice", "--state", "open", "--json", "title,number", "--limit", "5").Output()
	if len(prOut) > 2 {
		var prs []struct {
			Title  string `json:"title"`
			Number int    `json:"number"`
		}
		if json.Unmarshal(prOut, &prs) == nil && len(prs) > 0 {
			b.WriteString("OPEN PRs\n")
			for _, pr := range prs {
				b.WriteString(fmt.Sprintf("  #%d %s\n", pr.Number, pr.Title))
			}
			b.WriteString("\n")
		}
	}

	body := b.String()

	// Determine subject based on status
	subject := fmt.Sprintf("[fleet-digest] %s", time.Now().Format("2006-01-02 15:04"))
	for _, h := range healthMap {
		if h.Status == "quarantined" {
			subject += " -- QUARANTINE ACTIVE"
			break
		}
		if h.Status == "degraded" {
			subject += " -- DEGRADED"
			break
		}
	}

	// Send email
	emailTo := cfg.AlertEmail
	cmd := exec.Command("resend-email", "-m", body, emailTo, subject)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("[fleet-digest] email failed: %v\n%s", err, string(out))
		fmt.Print(body) // Print to stdout as fallback
		return
	}
	log.Printf("[fleet-digest] email sent to %s: %s", emailTo, strings.TrimSpace(string(out)))
}
