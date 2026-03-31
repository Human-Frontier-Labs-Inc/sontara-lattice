package main

import (
	"testing"
)

func TestClassifyAlertSyscheck(t *testing.T) {
	alert := WazuhAlert{Rule: WazuhRule{Groups: []string{"syscheck"}}}
	subject, secType := classifyAlert(alert)
	if subject != "fleet.security.fim" {
		t.Fatalf("expected fleet.security.fim, got %s", subject)
	}
	if secType != "fim" {
		t.Fatalf("expected fim, got %s", secType)
	}
}

func TestClassifyAlertFIM(t *testing.T) {
	alert := WazuhAlert{Rule: WazuhRule{Groups: []string{"fim"}}}
	subject, secType := classifyAlert(alert)
	if subject != "fleet.security.fim" {
		t.Fatalf("expected fleet.security.fim, got %s", subject)
	}
	if secType != "fim" {
		t.Fatalf("expected fim, got %s", secType)
	}
}

func TestClassifyAlertAuth(t *testing.T) {
	cases := []string{"authentication_failed", "sshd", "pam_unix", "sudo"}
	for _, group := range cases {
		alert := WazuhAlert{Rule: WazuhRule{Groups: []string{group}}}
		subject, secType := classifyAlert(alert)
		if subject != "fleet.security.auth" {
			t.Fatalf("group %q: expected fleet.security.auth, got %s", group, subject)
		}
		if secType != "auth" {
			t.Fatalf("group %q: expected auth, got %s", group, secType)
		}
	}
}

func TestClassifyAlertProcess(t *testing.T) {
	cases := []string{"process_monitor", "new_port"}
	for _, group := range cases {
		alert := WazuhAlert{Rule: WazuhRule{Groups: []string{group}}}
		subject, secType := classifyAlert(alert)
		if subject != "fleet.security.process" {
			t.Fatalf("group %q: expected fleet.security.process, got %s", group, subject)
		}
		if secType != "process" {
			t.Fatalf("group %q: expected process, got %s", group, secType)
		}
	}
}

func TestClassifyAlertNetwork(t *testing.T) {
	cases := []string{"network_scan", "non_tailscale_traffic"}
	for _, group := range cases {
		alert := WazuhAlert{Rule: WazuhRule{Groups: []string{group}}}
		subject, secType := classifyAlert(alert)
		if subject != "fleet.security.network" {
			t.Fatalf("group %q: expected fleet.security.network, got %s", group, subject)
		}
		if secType != "network" {
			t.Fatalf("group %q: expected network, got %s", group, secType)
		}
	}
}

func TestClassifyAlertQuarantine(t *testing.T) {
	alert := WazuhAlert{Rule: WazuhRule{Groups: []string{"quarantine"}}}
	subject, secType := classifyAlert(alert)
	if subject != "fleet.security.quarantine" {
		t.Fatalf("expected fleet.security.quarantine, got %s", subject)
	}
	if secType != "quarantine" {
		t.Fatalf("expected quarantine, got %s", secType)
	}
}

func TestClassifyAlertDefault(t *testing.T) {
	alert := WazuhAlert{Rule: WazuhRule{Groups: []string{"some_random_group"}}}
	subject, secType := classifyAlert(alert)
	if subject != "fleet.security.alert" {
		t.Fatalf("expected fleet.security.alert, got %s", subject)
	}
	if secType != "general" {
		t.Fatalf("expected general, got %s", secType)
	}
}

func TestClassifyAlertNoGroups(t *testing.T) {
	alert := WazuhAlert{Rule: WazuhRule{Groups: nil}}
	subject, secType := classifyAlert(alert)
	if subject != "fleet.security.alert" {
		t.Fatalf("expected fleet.security.alert, got %s", subject)
	}
	if secType != "general" {
		t.Fatalf("expected general, got %s", secType)
	}
}

func TestClassifyAlertQuarantinePriority(t *testing.T) {
	// Quarantine should take priority over other groups.
	alert := WazuhAlert{Rule: WazuhRule{Groups: []string{"syscheck", "quarantine"}}}
	subject, secType := classifyAlert(alert)
	if subject != "fleet.security.quarantine" {
		t.Fatalf("expected quarantine to take priority, got %s", subject)
	}
	if secType != "quarantine" {
		t.Fatalf("expected quarantine, got %s", secType)
	}
}

func TestSeverityFromLevel(t *testing.T) {
	cases := []struct {
		level    int
		expected string
	}{
		{1, "info"},
		{3, "info"},
		{5, "info"},
		{6, "warning"},
		{9, "warning"},
		{10, "critical"},
		{12, "critical"},
		{13, "quarantine"},
		{15, "quarantine"},
	}
	for _, tc := range cases {
		got := severityFromLevel(tc.level)
		if got != tc.expected {
			t.Errorf("severityFromLevel(%d) = %q, want %q", tc.level, got, tc.expected)
		}
	}
}

func TestNormalizeAgentName(t *testing.T) {
	origCfg := cfg
	defer func() { cfg = origCfg }()
	cfg.MachineName = "broker-host"

	cases := []struct {
		input, expected string
	}{
		{"wazuh.manager", "broker-host"},
		{"laptop-1.local", "laptop-1"},
		{"server-1", "server-1"},
		{"pi-node.local", "pi-node"},
	}
	for _, tc := range cases {
		got := normalizeAgentName(tc.input)
		if got != tc.expected {
			t.Errorf("normalizeAgentName(%q) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}

func TestAlertToSecurityEvent(t *testing.T) {
	origCfg := cfg
	defer func() { cfg = origCfg }()
	cfg.MachineName = "broker-host"

	alert := WazuhAlert{
		Timestamp: "2026-01-15T10:30:00Z",
		Rule: WazuhRule{
			Level:       7,
			Description: "File modified",
			ID:          "550",
			Groups:      []string{"syscheck", "fim"},
		},
		Agent: WazuhAgent{
			ID:   "001",
			Name: "laptop-1.local",
			IP:   "10.0.0.5",
		},
		SyscheckData: &SyscheckEvent{
			Path:  "/etc/passwd",
			Event: "modified",
		},
	}

	event := alertToSecurityEvent(alert)

	if event.Type != "fim" {
		t.Fatalf("expected type fim, got %s", event.Type)
	}
	if event.Severity != "warning" {
		t.Fatalf("expected warning for level 7, got %s", event.Severity)
	}
	if event.Machine != "laptop-1" {
		t.Fatalf("expected laptop-1, got %s", event.Machine)
	}
	if event.AgentID != "001" {
		t.Fatalf("expected agent ID 001, got %s", event.AgentID)
	}
	if event.RuleID != "550" {
		t.Fatalf("expected rule ID 550, got %s", event.RuleID)
	}
	if event.FilePath != "/etc/passwd" {
		t.Fatalf("expected file path /etc/passwd, got %s", event.FilePath)
	}
	if event.SourceIP != "10.0.0.5" {
		t.Fatalf("expected source IP 10.0.0.5, got %s", event.SourceIP)
	}
	if event.Timestamp != "2026-01-15T10:30:00Z" {
		t.Fatalf("expected timestamp preserved, got %s", event.Timestamp)
	}
}

func TestErrStr(t *testing.T) {
	var e errStr = "test error"
	if e.Error() != "test error" {
		t.Fatalf("expected 'test error', got %q", e.Error())
	}
}

func TestAlertToSecurityEventNoSyscheck(t *testing.T) {
	alert := WazuhAlert{
		Rule: WazuhRule{
			Level:       3,
			Description: "Login success",
			ID:          "5501",
			Groups:      []string{"authentication"},
		},
		Agent: WazuhAgent{
			ID:   "002",
			Name: "workstation-1",
		},
	}

	event := alertToSecurityEvent(alert)

	if event.Type != "auth" {
		t.Fatalf("expected auth, got %s", event.Type)
	}
	if event.FilePath != "" {
		t.Fatalf("expected empty file path, got %s", event.FilePath)
	}
	if event.SourceIP != "" {
		t.Fatalf("expected empty source IP, got %s", event.SourceIP)
	}
}
