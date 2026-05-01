package policy

import (
	"math"
	"strings"
	"testing"
)

func TestEstimateCrackTimes_Length(t *testing.T) {
	got := EstimateCrackTimes(80)
	if len(got) != len(AttackerProfiles) {
		t.Errorf("got %d estimates, want %d", len(got), len(AttackerProfiles))
	}
}

func TestEstimateCrackTimes_OrderOfMagnitudeSanity(t *testing.T) {
	// At 80 bits, average guesses = 2^79 ≈ 6e23.
	// online-throttled (1e2 g/s) → 6e21 s ≈ 2e14 years (much longer than universe age).
	// nation-state (1e15 g/s) → 6e8 s ≈ 19 years.
	estimates := EstimateCrackTimes(80)
	online := estimates[0]                // online-throttled-v1
	nation := estimates[len(estimates)-1] // nation-state-v1

	if online.ProfileID != "online-throttled-v1" {
		t.Errorf("first profile id = %q", online.ProfileID)
	}
	if nation.ProfileID != "nation-state-v1" {
		t.Errorf("last profile id = %q", nation.ProfileID)
	}
	if !(online.Seconds > nation.Seconds*1e8) {
		t.Errorf("expected online >> nation by ~13 orders, got online=%v nation=%v",
			online.Seconds, nation.Seconds)
	}
}

func TestEstimateCrackTimes_ZeroEntropy(t *testing.T) {
	if got := EstimateCrackTimes(0); got != nil {
		t.Errorf("EstimateCrackTimes(0) = %v, want nil", got)
	}
	if got := EstimateCrackTimes(-5); got != nil {
		t.Errorf("EstimateCrackTimes(-5) = %v, want nil", got)
	}
}

func TestEstimateCrackTimes_HumanReadablePopulated(t *testing.T) {
	for _, e := range EstimateCrackTimes(128) {
		if e.HumanReadable == "" {
			t.Errorf("empty HumanReadable for %s", e.ProfileID)
		}
	}
}

func TestHumanizeDuration_Bands(t *testing.T) {
	tests := []struct {
		secs float64
		want string // substring expected
	}{
		{0, "instant"},
		{0.0005, "instant"},
		{0.5, "milliseconds"},
		{30, "seconds"},
		{120, "minutes"},
		{7200, "hours"},
		{86400 * 5, "days"},
		{86400 * 365.25 * 2, "years"},
		{86400 * 365.25 * 200, "centuries"},
		{86400 * 365.25 * 5000, "millennia"},
		{86400 * 365.25 * 1e15, "age of the universe"},
		{math.Inf(1), "forever"},
		{math.NaN(), "forever"},
	}
	for _, tt := range tests {
		got := humanizeDuration(tt.secs)
		if !strings.Contains(got, tt.want) {
			t.Errorf("humanize(%v) = %q, want substring %q", tt.secs, got, tt.want)
		}
	}
}

func TestEstimateCrackTimes_HighEntropyDoesNotPanic(t *testing.T) {
	// 1024 bits is well past math.Pow's headroom for 2^N as a float64.
	// We must not panic and the human-readable string should reflect overflow.
	got := EstimateCrackTimes(1024)
	for _, e := range got {
		if e.HumanReadable == "" {
			t.Errorf("empty HumanReadable at high entropy: %+v", e)
		}
	}
}

func TestAttackerProfiles_StableOrder(t *testing.T) {
	// Profiles should be in strictly increasing guess-rate order so consumers
	// can iterate and trust scenario severity.
	for i := 1; i < len(AttackerProfiles); i++ {
		if AttackerProfiles[i].GuessesPerSec <= AttackerProfiles[i-1].GuessesPerSec {
			t.Errorf("profiles not strictly increasing at %d: %v > %v",
				i, AttackerProfiles[i-1], AttackerProfiles[i])
		}
	}
}
