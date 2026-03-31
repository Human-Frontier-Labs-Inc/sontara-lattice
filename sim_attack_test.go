package main

import (
	"testing"
)

func initTestFleetTargets() {
	cfg.FleetTargets = map[string]string{
		"server-1": "server-1",
		"server-2": "server-2",
		"laptop-1": "laptop-1",
	}
	// Refresh simSSHTargets since it's initialized at package level.
	simSSHTargets = fleetSSHTargets()
}

func TestParseSimArgs(t *testing.T) {
	initTestFleetTargets()
	sc, err := parseSimArgs([]string{"brute-force"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sc.scenario != "brute-force" {
		t.Fatalf("expected brute-force, got %s", sc.scenario)
	}
	if len(sc.targets) != 1 {
		t.Fatalf("expected 1 default target, got %v", sc.targets)
	}
	if sc.dryRun {
		t.Fatal("expected dryRun false")
	}
}

func TestParseSimArgsWithFlags(t *testing.T) {
	initTestFleetTargets()
	sc, err := parseSimArgs([]string{"brute-force", "--target=server-1", "--dry-run"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sc.scenario != "brute-force" {
		t.Fatalf("expected brute-force, got %s", sc.scenario)
	}
	if len(sc.targets) != 1 || sc.targets[0] != "server-1" {
		t.Fatalf("expected target server-1, got %v", sc.targets)
	}
	if !sc.dryRun {
		t.Fatal("expected dryRun true")
	}
}

func TestParseSimArgsMultipleTargets(t *testing.T) {
	initTestFleetTargets()
	sc, err := parseSimArgs([]string{"lateral-movement", "--target=server-1,server-2"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sc.targets) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(sc.targets))
	}
}

func TestParseSimArgsNoScenario(t *testing.T) {
	initTestFleetTargets()
	_, err := parseSimArgs([]string{})
	if err == nil {
		t.Fatal("expected error for no scenario")
	}
}

func TestParseSimArgsUnknownFlag(t *testing.T) {
	initTestFleetTargets()
	_, err := parseSimArgs([]string{"brute-force", "--bad-flag"})
	if err == nil {
		t.Fatal("expected error for unknown flag")
	}
}

func TestParseSimArgsUnknownTarget(t *testing.T) {
	initTestFleetTargets()
	_, err := parseSimArgs([]string{"brute-force", "--target=unknown-machine"})
	if err == nil {
		t.Fatal("expected error for unknown target")
	}
}

func TestParseSimArgsAll(t *testing.T) {
	initTestFleetTargets()
	sc, err := parseSimArgs([]string{"--all"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sc.scenario != "--all" {
		t.Fatalf("expected --all, got %s", sc.scenario)
	}
}
