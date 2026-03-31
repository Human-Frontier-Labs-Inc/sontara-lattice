package main

import (
	"os"
	"strings"
	"testing"
)

func TestMatchSubject(t *testing.T) {
	cases := []struct {
		pattern, eventType string
		expected           bool
	}{
		{"fleet.>", "peer_joined", true},
		{">", "anything", true},
		{"fleet.peer.>", "peer_joined", false},         // "peer_joined" doesn't contain "fleet.peer"
		{"fleet.security.>", "fleet.security.fim", true}, // contains "fleet.security"
		{"fleet.peer", "fleet.peer.joined", true},
	}
	for _, tc := range cases {
		got := matchSubject(tc.pattern, tc.eventType)
		if got != tc.expected {
			t.Errorf("matchSubject(%q, %q) = %v, want %v", tc.pattern, tc.eventType, got, tc.expected)
		}
	}
}

func TestFilterDaemonEnv(t *testing.T) {
	// Set some test env vars.
	t.Setenv("PATH", "/usr/bin")
	t.Setenv("HOME", "/home/test")
	t.Setenv("CLAUDE_PEERS_TOKEN", "secret-token")
	t.Setenv("OPENAI_API_KEY", "sk-test")
	t.Setenv("SOME_RANDOM_VAR", "should-be-filtered")

	filtered := filterDaemonEnv()

	has := func(key string) bool {
		for _, e := range filtered {
			if strings.HasPrefix(e, key+"=") {
				return true
			}
		}
		return false
	}

	if !has("PATH") {
		t.Error("expected PATH in filtered env")
	}
	if !has("HOME") {
		t.Error("expected HOME in filtered env")
	}
	if !has("OPENAI_API_KEY") {
		t.Error("expected OPENAI_API_KEY in filtered env")
	}
	if has("CLAUDE_PEERS_TOKEN") {
		t.Error("CLAUDE_PEERS_TOKEN should be filtered out")
	}
	if has("SOME_RANDOM_VAR") {
		t.Error("SOME_RANDOM_VAR should be filtered out")
	}
}

func TestExtractAgentOutput(t *testing.T) {
	// Test JSON extraction.
	raw := `Starting agent...
Loading config...
{"Status":"complete","Outputs":{"goal":"Fleet is healthy, all 4 machines online"},"Error":""}`

	got := extractAgentOutput(raw)
	if got != "Fleet is healthy, all 4 machines online" {
		t.Fatalf("expected extracted output, got %q", got)
	}
}

func TestExtractAgentOutputFallback(t *testing.T) {
	// No JSON -- falls back to tail of raw output.
	raw := "just some plain text output"
	got := extractAgentOutput(raw)
	if got != raw {
		t.Fatalf("expected raw fallback, got %q", got)
	}
}

func TestExtractAgentOutputLong(t *testing.T) {
	// Long output without JSON -- should truncate to last 500 chars.
	raw := strings.Repeat("x", 1000)
	got := extractAgentOutput(raw)
	if len(got) != 500 {
		t.Fatalf("expected 500 char truncation, got %d", len(got))
	}
}

func TestExtractAgentOutputMultipleGoals(t *testing.T) {
	raw := `
{"Outputs":{"check_health":"all good","check_peers":"5 peers online"}}`

	got := extractAgentOutput(raw)
	// Should contain both outputs joined by " | ".
	if !strings.Contains(got, "all good") || !strings.Contains(got, "5 peers online") {
		t.Fatalf("expected both goal outputs, got %q", got)
	}
}

func TestExtractAgentOutputEmptyOutputs(t *testing.T) {
	raw := `{"Outputs":{}}`
	got := extractAgentOutput(raw)
	// Empty outputs -> falls back to raw.
	_ = got // Just verify no panic.
}

func TestFilterDaemonEnvIncludesSSHAuthSock(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "/tmp/ssh-agent.sock")
	filtered := filterDaemonEnv()
	for _, e := range filtered {
		if strings.HasPrefix(e, "SSH_AUTH_SOCK=") {
			return
		}
	}
	t.Error("expected SSH_AUTH_SOCK in filtered env")
}

func TestFilterDaemonEnvEmptyAllowed(t *testing.T) {
	// Clear all known env vars to verify no crash.
	for _, key := range []string{"PATH", "HOME", "USER", "SHELL"} {
		os.Unsetenv(key)
	}
	filtered := filterDaemonEnv()
	_ = filtered // Just verify no panic.
}
