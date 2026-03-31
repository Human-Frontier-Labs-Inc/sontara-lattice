package main

import (
	"testing"
)

func TestLevelForStatus(t *testing.T) {
	cases := []struct {
		status, expected string
	}{
		{"up", "info"},
		{"running", "info"},
		{"online", "info"},
		{"degraded", "warn"},
		{"unhealthy", "warn"},
		{"down", "error"},
		{"unknown", "error"},
		{"", "error"},
	}
	for _, tc := range cases {
		got := levelForStatus(tc.status)
		if got != tc.expected {
			t.Errorf("levelForStatus(%q) = %q, want %q", tc.status, got, tc.expected)
		}
	}
}

func TestStringSliceEqual(t *testing.T) {
	cases := []struct {
		a, b     []string
		expected bool
	}{
		{nil, nil, true},
		{[]string{}, []string{}, true},
		{[]string{"a"}, []string{"a"}, true},
		{[]string{"a", "b"}, []string{"a", "b"}, true},
		{[]string{"a"}, []string{"b"}, false},
		{[]string{"a"}, []string{"a", "b"}, false},
		{[]string{"a", "b"}, []string{"b", "a"}, false},
	}
	for _, tc := range cases {
		got := stringSliceEqual(tc.a, tc.b)
		if got != tc.expected {
			t.Errorf("stringSliceEqual(%v, %v) = %v, want %v", tc.a, tc.b, got, tc.expected)
		}
	}
}
