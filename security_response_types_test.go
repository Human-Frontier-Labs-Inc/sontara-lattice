package main

import (
	"testing"
)

func TestIncidentTier(t *testing.T) {
	cases := []struct {
		incident IncidentType
		expected ResponseTier
	}{
		{IncidentBruteForce, TierContain},
		{IncidentBinaryTamper, TierContain},
		{IncidentRogueService, TierAuto},
		{IncidentCredentialTheft, TierApproval},
		{IncidentLateralMovement, TierApproval},
		{IncidentQuarantine, TierAuto}, // default case
		{"unknown_incident", TierAuto}, // default case
	}
	for _, tc := range cases {
		got := incidentTier(tc.incident)
		if got != tc.expected {
			t.Errorf("incidentTier(%q) = %d, want %d", tc.incident, got, tc.expected)
		}
	}
}

func TestResponseTierValues(t *testing.T) {
	if TierAuto != 1 {
		t.Errorf("TierAuto = %d, want 1", TierAuto)
	}
	if TierContain != 2 {
		t.Errorf("TierContain = %d, want 2", TierContain)
	}
	if TierApproval != 3 {
		t.Errorf("TierApproval = %d, want 3", TierApproval)
	}
}
