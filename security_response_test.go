package main

import (
	"testing"
	"time"
)

func testResponseDaemon() *ResponseDaemon {
	return &ResponseDaemon{
		incidents:     make(map[string]*Incident),
		ipBlocks:      make(map[string]time.Time),
		emailThrottle: make(map[string]time.Time),
		sshTargets:    make(map[string]string),
		machineOS:     make(map[string]string),
	}
}

func TestClassifyIncidentQuarantine(t *testing.T) {
	rd := testResponseDaemon()

	cases := []struct {
		name     string
		event    FleetEvent
		secEvent SecurityEvent
		expected IncidentType
	}{
		{
			"quarantine brute force",
			FleetEvent{Type: "quarantine", Data: "brute force detected"},
			SecurityEvent{},
			IncidentBruteForce,
		},
		{
			"quarantine credential theft",
			FleetEvent{Type: "quarantine", Summary: "credential theft"},
			SecurityEvent{},
			IncidentCredentialTheft,
		},
		{
			"quarantine distributed/lateral",
			FleetEvent{Type: "quarantine", Data: "distributed attack"},
			SecurityEvent{},
			IncidentLateralMovement,
		},
		{
			"quarantine generic",
			FleetEvent{Type: "quarantine", Data: "something else"},
			SecurityEvent{},
			IncidentQuarantine,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := rd.classifyIncident(tc.event, tc.secEvent)
			if got != tc.expected {
				t.Fatalf("expected %q, got %q", tc.expected, got)
			}
		})
	}
}

func TestClassifyIncidentBinaryTamper(t *testing.T) {
	rd := testResponseDaemon()

	got := rd.classifyIncident(
		FleetEvent{Type: "security"},
		SecurityEvent{RuleID: "100101", Level: 13},
	)
	if got != IncidentBinaryTamper {
		t.Fatalf("expected binary_tamper, got %q", got)
	}

	// Level too low -- should not match.
	got = rd.classifyIncident(
		FleetEvent{Type: "security"},
		SecurityEvent{RuleID: "100101", Level: 12},
	)
	if got == IncidentBinaryTamper {
		t.Fatal("level 12 should not trigger binary_tamper")
	}
}

func TestClassifyIncidentRogueService(t *testing.T) {
	rd := testResponseDaemon()

	got := rd.classifyIncident(
		FleetEvent{Type: "security"},
		SecurityEvent{RuleID: "100130"},
	)
	if got != IncidentRogueService {
		t.Fatalf("expected rogue_service, got %q", got)
	}
}

func TestClassifyIncidentCriticalSeverity(t *testing.T) {
	rd := testResponseDaemon()

	got := rd.classifyIncident(
		FleetEvent{Type: "security"},
		SecurityEvent{Severity: "critical"},
	)
	if got != IncidentQuarantine {
		t.Fatalf("expected quarantine for critical severity, got %q", got)
	}
}

func TestClassifyIncidentNoMatch(t *testing.T) {
	rd := testResponseDaemon()

	got := rd.classifyIncident(
		FleetEvent{Type: "security"},
		SecurityEvent{Severity: "warning", RuleID: "12345"},
	)
	if got != "" {
		t.Fatalf("expected empty for unmatched, got %q", got)
	}
}
