package main

import (
	"strings"
	"testing"
)

// The startup line must tell the operator how to change the state, and the
// advice must actually work. Two ways to get that wrong:
//
//   - Referring to the endpoint by its log field ("POST to admin_url")
//     renders as an unsubstituted template:
//     "POST to admin_url admin_url=http://127.0.0.1:9091/...".
//   - Telling the operator to run `threat-engine enforce on` when the flag is
//     locked by the environment. That toggle is refused with 403, so the
//     advice points at a command that cannot work.
func TestEnforcementStartupMessageNamesTheEndpoint(t *testing.T) {
	msg := enforcementStartupMessage(false, false, "9091")

	if !strings.Contains(msg, "http://127.0.0.1:9091/enforcement?enabled=true") {
		t.Fatalf("the message must name the endpoint it wants called, got: %q", msg)
	}
	if strings.Contains(msg, "admin_url") {
		t.Fatalf("the message must not refer to the endpoint by its log field, got: %q", msg)
	}
}

func TestEnforcementStartupMessageUsesTheConfiguredAdminPort(t *testing.T) {
	msg := enforcementStartupMessage(false, false, "9999")

	if !strings.Contains(msg, "127.0.0.1:9999") {
		t.Fatalf("the message must use the configured admin port, got: %q", msg)
	}
	if strings.Contains(msg, "9091") {
		t.Fatalf("the message must not hardcode a port, got: %q", msg)
	}
}

func TestEnforcementStartupMessageOffersTheToggleWhenUnlocked(t *testing.T) {
	msg := enforcementStartupMessage(false, false, "9091")

	if !strings.Contains(msg, "threat-engine enforce on") {
		t.Fatalf("the disabled message must name the toggle, got: %q", msg)
	}
}

func TestEnforcementStartupMessageOffersNoToggleWhenLocked(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		msg := enforcementStartupMessage(enabled, true, "9091")

		if !strings.Contains(msg, "locked") {
			t.Fatalf("a locked daemon must say so, got: %q", msg)
		}
		// A locked daemon refuses runtime toggles with 403, so advising one
		// would point the operator at a command that cannot work.
		if strings.Contains(msg, "threat-engine enforce on") || strings.Contains(msg, "threat-engine enforce off") {
			t.Fatalf("a locked daemon must not advertise a runtime toggle, got: %q", msg)
		}
	}
}

func TestEnforcementStartupMessageSaysWhatIsHappening(t *testing.T) {
	off := enforcementStartupMessage(false, false, "9091")
	if !strings.Contains(off, "DISABLED") || !strings.Contains(off, "no kernel rules") {
		t.Fatalf("the disabled message must state that nothing is filtered, got: %q", off)
	}

	on := enforcementStartupMessage(true, false, "9091")
	if !strings.Contains(on, "ENABLED") || !strings.Contains(on, "raw:PREROUTING") {
		t.Fatalf("the enabled message must state that packets are dropped, got: %q", on)
	}
	if !strings.Contains(on, "threat-engine enforce off") {
		t.Fatalf("the enabled message must name the way back, got: %q", on)
	}
}
