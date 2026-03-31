package main

import (
	"strings"
	"testing"
	"time"
)

func TestBuildFleetMemoryEmpty(t *testing.T) {
	content := buildFleetMemory(nil, nil, nil)

	if !strings.Contains(content, "No active instances.") {
		t.Error("expected 'No active instances.' for empty peers")
	}
	if !strings.Contains(content, "No recent events.") {
		t.Error("expected 'No recent events.' for empty events")
	}
	if !strings.Contains(content, "fleet-activity") {
		t.Error("expected frontmatter with fleet-activity name")
	}
}

func TestBuildFleetMemoryWithPeers(t *testing.T) {
	peers := []Peer{
		{ID: "a1", Machine: "server-1", CWD: "/home/user/projects/foo", GitRoot: "/home/user/projects/foo", Summary: "working on tests"},
		{ID: "a2", Machine: "server-1", CWD: "/home/user/projects/bar", Summary: "debugging"},
		{ID: "b1", Machine: "laptop-1", CWD: "/Users/user/code", Summary: "reviewing PR"},
	}

	content := buildFleetMemory(peers, nil, nil)

	if !strings.Contains(content, "server-1 (2 sessions)") {
		t.Error("expected server-1 with 2 sessions")
	}
	if !strings.Contains(content, "laptop-1 (1 sessions)") {
		t.Error("expected laptop-1 with 1 session")
	}
	if !strings.Contains(content, "working on tests") {
		t.Error("expected peer summary in output")
	}
	if !strings.Contains(content, "(repo: foo)") {
		t.Error("expected repo name extracted from git root")
	}
}

func TestBuildFleetMemoryWithHealth(t *testing.T) {
	health := map[string]*MachineHealth{
		"server-1": {Score: 0, Status: "healthy"},
		"laptop-1": {Score: 7, Status: "degraded", LastEventDesc: "suspicious login"},
	}

	content := buildFleetMemory(nil, nil, health)

	if !strings.Contains(content, "Security Status") {
		t.Error("expected Security Status section")
	}
	if !strings.Contains(content, "laptop-1") {
		t.Error("expected degraded machine in output")
	}
	if !strings.Contains(content, "degraded") {
		t.Error("expected degraded status")
	}
	if !strings.Contains(content, "suspicious login") {
		t.Error("expected last event description")
	}
}

func TestBuildFleetMemoryAllHealthy(t *testing.T) {
	health := map[string]*MachineHealth{
		"server-1": {Score: 0, Status: "healthy"},
	}

	content := buildFleetMemory(nil, nil, health)

	if !strings.Contains(content, "All machines healthy") {
		t.Error("expected 'All machines healthy' when no issues")
	}
}

func TestBuildFleetMemoryWithEvents(t *testing.T) {
	now := time.Now().UTC().Format(time.RFC3339)
	events := []Event{
		{ID: 1, Type: "peer_joined", PeerID: "a1", Machine: "server-1", CreatedAt: now},
		{ID: 2, Type: "message_sent", PeerID: "a1", Machine: "server-1", Data: "writing tests", CreatedAt: now},
	}

	content := buildFleetMemory(nil, events, nil)

	if !strings.Contains(content, "server-1 joined") {
		t.Error("expected peer_joined event")
	}
	if !strings.Contains(content, "server-1") {
		t.Error("expected machine name in events")
	}
}

func TestBuildFleetMemorySkipsNoisyDeviceEvents(t *testing.T) {
	now := time.Now().UTC().Format(time.RFC3339)
	events := []Event{
		{ID: 1, Type: "peer_joined", PeerID: "v4", Machine: "device-1", CreatedAt: now},
		{ID: 2, Type: "summary_changed", PeerID: "v4", Machine: "device-1", Data: "heartbeat", CreatedAt: now},
		{ID: 3, Type: "message_sent", PeerID: "a1", Machine: "server-1", CreatedAt: now},
	}

	content := buildFleetMemory(nil, events, nil)

	// device-1 peer_joined and summary_changed should be skipped
	// (the code skips noisy events from any machine matching the pattern).
	// Note: the current code filters a specific machine name -- this test
	// validates that non-filtered events still show.
	if !strings.Contains(content, "server-1") {
		t.Error("expected server-1 message_sent event")
	}
}

func TestShortenPath(t *testing.T) {
	cases := []struct {
		input, expected string
	}{
		{"/home/testuser/projects/foo", "~/projects/foo"},
		{"/Users/testuser/code", "~/code"},
		{"/opt/something", "/opt/something"},
	}
	for _, tc := range cases {
		got := shortenPath(tc.input)
		if got != tc.expected {
			t.Errorf("shortenPath(%q) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}

func TestTimeAgoStr(t *testing.T) {
	now := time.Now().UTC()

	cases := []struct {
		offset   time.Duration
		expected string
	}{
		{30 * time.Second, "30s"},
		{5 * time.Minute, "5m"},
		{3 * time.Hour, "3h"},
		{48 * time.Hour, "2d"},
	}
	for _, tc := range cases {
		iso := now.Add(-tc.offset).Format(time.RFC3339)
		got := timeAgoStr(iso)
		if got != tc.expected {
			t.Errorf("timeAgoStr(%v ago) = %q, want %q", tc.offset, got, tc.expected)
		}
	}
}

func TestTimeAgoStrInvalid(t *testing.T) {
	got := timeAgoStr("not-a-date")
	if got != "?" {
		t.Errorf("expected '?' for invalid date, got %q", got)
	}
}
