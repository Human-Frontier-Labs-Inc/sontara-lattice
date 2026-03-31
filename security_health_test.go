package main

import (
	"testing"
)

func TestUpdateMachineHealthInfo(t *testing.T) {
	b := testBroker(t)

	b.updateMachineHealth(SecurityEvent{
		Machine:     "test-machine",
		Severity:    "info",
		Description: "normal event",
		Timestamp:   nowISO(),
	})

	h := b.getMachineHealth("test-machine")
	if h == nil {
		t.Fatal("expected health record to exist")
	}
	if h.Score != 0 {
		t.Fatalf("expected score 0 for info severity, got %d", h.Score)
	}
	if h.Status != "healthy" {
		t.Fatalf("expected healthy status, got %s", h.Status)
	}
}

func TestUpdateMachineHealthWarning(t *testing.T) {
	b := testBroker(t)

	// A single warning adds 1 to score.
	b.updateMachineHealth(SecurityEvent{
		Machine:  "test-machine",
		Severity: "warning",
	})
	h := b.getMachineHealth("test-machine")
	if h.Score != 1 {
		t.Fatalf("expected score 1, got %d", h.Score)
	}

	// Warnings cap at 9 -- never quarantine on their own.
	for i := 0; i < 20; i++ {
		b.updateMachineHealth(SecurityEvent{
			Machine:  "test-machine",
			Severity: "warning",
		})
	}
	h = b.getMachineHealth("test-machine")
	if h.Score > 9 {
		t.Fatalf("expected warning score capped at 9, got %d", h.Score)
	}
	if h.Status == "quarantined" {
		t.Fatal("warnings alone should not quarantine")
	}
}

func TestUpdateMachineHealthCritical(t *testing.T) {
	b := testBroker(t)

	b.updateMachineHealth(SecurityEvent{
		Machine:  "test-machine",
		Severity: "critical",
	})
	h := b.getMachineHealth("test-machine")
	if h.Score != 10 {
		t.Fatalf("expected score 10, got %d", h.Score)
	}
	if h.Status != "quarantined" {
		t.Fatalf("expected quarantined status at score 10, got %s", h.Status)
	}
}

func TestUpdateMachineHealthQuarantine(t *testing.T) {
	b := testBroker(t)

	b.updateMachineHealth(SecurityEvent{
		Machine:  "test-machine",
		Severity: "quarantine",
	})
	h := b.getMachineHealth("test-machine")
	if h.Status != "quarantined" {
		t.Fatalf("expected immediate quarantine, got %s", h.Status)
	}
	if h.DemotedAt == "" {
		t.Fatal("expected DemotedAt to be set on quarantine")
	}
}

func TestDecayHealthScores(t *testing.T) {
	b := testBroker(t)

	// Set up a machine with score 8 (degraded).
	b.updateMachineHealth(SecurityEvent{Machine: "m1", Severity: "warning"})
	// Add 7 more warnings to reach 8.
	for i := 0; i < 7; i++ {
		b.updateMachineHealth(SecurityEvent{Machine: "m1", Severity: "warning"})
	}
	h := b.getMachineHealth("m1")
	if h.Score != 8 {
		t.Fatalf("setup: expected score 8, got %d", h.Score)
	}

	b.decayHealthScores()

	h = b.getMachineHealth("m1")
	if h.Score != 6 {
		t.Fatalf("expected score 6 after decay, got %d", h.Score)
	}
}

func TestDecayDoesNotAffectQuarantined(t *testing.T) {
	b := testBroker(t)

	b.updateMachineHealth(SecurityEvent{Machine: "m1", Severity: "quarantine"})
	b.decayHealthScores()

	h := b.getMachineHealth("m1")
	if h.Status != "quarantined" {
		t.Fatalf("quarantined machine should not decay, got status %s", h.Status)
	}
}

func TestGetMachineHealthNil(t *testing.T) {
	b := testBroker(t)

	h := b.getMachineHealth("nonexistent")
	if h != nil {
		t.Fatal("expected nil for unknown machine")
	}
}

func TestUnquarantine(t *testing.T) {
	b := testBroker(t)

	b.updateMachineHealth(SecurityEvent{Machine: "m1", Severity: "quarantine"})
	if b.getMachineHealth("m1").Status != "quarantined" {
		t.Fatal("expected quarantined")
	}

	b.unquarantine("m1")

	h := b.getMachineHealth("m1")
	if h.Status != "healthy" {
		t.Fatalf("expected healthy after unquarantine, got %s", h.Status)
	}
	if h.Score != 0 {
		t.Fatalf("expected score 0 after unquarantine, got %d", h.Score)
	}
	if h.DemotedAt != "" {
		t.Fatal("expected DemotedAt cleared after unquarantine")
	}
}

func TestUnquarantineNonexistent(t *testing.T) {
	b := testBroker(t)
	// Should not panic.
	b.unquarantine("nonexistent")
}

func TestGetHealthScore(t *testing.T) {
	b := testBroker(t)

	if score := b.getHealthScore("nonexistent"); score != 0 {
		t.Fatalf("expected 0 for unknown machine, got %d", score)
	}

	b.updateMachineHealth(SecurityEvent{Machine: "m1", Severity: "warning"})
	if score := b.getHealthScore("m1"); score != 1 {
		t.Fatalf("expected 1, got %d", score)
	}
}

func TestHealthEventRingBuffer(t *testing.T) {
	b := testBroker(t)

	// Push 15 events -- ring buffer should keep last 10.
	for i := 0; i < 15; i++ {
		b.updateMachineHealth(SecurityEvent{
			Machine:     "m1",
			Severity:    "warning",
			Description: "event",
		})
	}

	h := b.getMachineHealth("m1")
	if len(h.Events) != 10 {
		t.Fatalf("expected 10 events in ring buffer, got %d", len(h.Events))
	}
}

func TestDegradedStatus(t *testing.T) {
	b := testBroker(t)

	// Score 5 = degraded.
	for i := 0; i < 5; i++ {
		b.updateMachineHealth(SecurityEvent{Machine: "m1", Severity: "warning"})
	}
	h := b.getMachineHealth("m1")
	if h.Status != "degraded" {
		t.Fatalf("expected degraded at score 5, got %s", h.Status)
	}
}

func TestDecayRecalculatesStatus(t *testing.T) {
	b := testBroker(t)

	// Set score to 6 (degraded).
	for i := 0; i < 6; i++ {
		b.updateMachineHealth(SecurityEvent{Machine: "m1", Severity: "warning"})
	}
	if b.getMachineHealth("m1").Status != "degraded" {
		t.Fatal("expected degraded at score 6")
	}

	// Decay by 2 -> score 4 -> healthy.
	b.decayHealthScores()

	h := b.getMachineHealth("m1")
	if h.Status != "healthy" {
		t.Fatalf("expected healthy after decay to score 4, got %s (score %d)", h.Status, h.Score)
	}
}
