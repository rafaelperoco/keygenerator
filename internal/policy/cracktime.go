package policy

import (
	"fmt"
	"math"
)

// AttackerProfile names a hash-cracking scenario with a representative
// guesses-per-second rate. Profiles span 9 orders of magnitude and reflect
// 2024-2026 capabilities; updating these is a versioned schema change.
type AttackerProfile struct {
	ID            string  `json:"id"`
	Description   string  `json:"description"`
	GuessesPerSec float64 `json:"guesses_per_second"`
}

// AttackerProfiles is the canonical set used to compute CrackTimeEstimates.
// Adding new profiles is non-breaking; changing rates of an existing ID is
// breaking and would require a schema bump (and incrementing the *-v1 suffix
// in IDs to track the new calibration).
var AttackerProfiles = []AttackerProfile{
	{
		ID:            "online-throttled-v1",
		Description:   "Online attack against a rate-limited verifier (e.g. login API with 100 attempts/sec global limit)",
		GuessesPerSec: 1e2,
	},
	{
		ID:            "slow-kdf-v1",
		Description:   "Offline attack against a slow KDF at OWASP 2024 settings (Argon2id m=19MiB t=2 p=1, ~1k guesses/sec/GPU)",
		GuessesPerSec: 1e3,
	},
	{
		ID:            "bcrypt-cost12-v1",
		Description:   "Offline attack against bcrypt cost=12 on a single RTX 4090 (Specops 2024, ~50k guesses/sec)",
		GuessesPerSec: 5e4,
	},
	{
		ID:            "fast-hash-single-gpu-v1",
		Description:   "Offline attack against unsalted SHA-256 on a single RTX 4090 (~100 billion guesses/sec)",
		GuessesPerSec: 1e11,
	},
	{
		ID:            "nation-state-v1",
		Description:   "Adversary fielding 10,000 RTX 4090s against a fast hash (~1 quadrillion guesses/sec)",
		GuessesPerSec: 1e15,
	},
}

// CrackTimeEstimate is one attacker scenario applied to a credential's
// entropy. Seconds is the projected time to find the password by exhaustive
// search, in the average case (half the space).
type CrackTimeEstimate struct {
	ProfileID     string  `json:"profile_id"`
	Description   string  `json:"description"`
	Seconds       float64 `json:"seconds"`
	HumanReadable string  `json:"human_readable"`
}

// EstimateCrackTimes returns one CrackTimeEstimate per attacker profile for
// a credential of the given entropy. Returns nil for non-positive entropy.
func EstimateCrackTimes(entropyBits float64) []CrackTimeEstimate {
	if entropyBits <= 0 {
		return nil
	}
	// Average case: attacker finds the password after searching half the
	// space. Use math.Pow for accuracy; the result can exceed math.MaxFloat64
	// for entropy >~1023 bits, in which case we report +Inf.
	avgGuesses := math.Pow(2, entropyBits-1)

	out := make([]CrackTimeEstimate, 0, len(AttackerProfiles))
	for _, p := range AttackerProfiles {
		secs := avgGuesses / p.GuessesPerSec
		out = append(out, CrackTimeEstimate{
			ProfileID:     p.ID,
			Description:   p.Description,
			Seconds:       secs,
			HumanReadable: humanizeDuration(secs),
		})
	}
	return out
}

// humanizeDuration converts seconds to a human-readable string with a
// large-magnitude tail (millennia, eons) so very strong credentials
// produce a sensible message rather than scientific notation.
func humanizeDuration(seconds float64) string {
	if math.IsInf(seconds, 1) || math.IsNaN(seconds) {
		return "essentially forever (overflow)"
	}
	if seconds < 1 {
		if seconds < 1e-3 {
			return "instant (microseconds)"
		}
		ms := seconds * 1000
		return fmt.Sprintf("%.0f milliseconds", ms)
	}

	const (
		minute     = 60.0
		hour       = 60 * minute
		day        = 24 * hour
		year       = 365.25 * day
		century    = 100 * year
		millennium = 1000 * year
		ageOfUni   = 13.8e9 * year // 13.8 billion years
	)

	switch {
	case seconds < minute:
		return fmt.Sprintf("%.0f seconds", seconds)
	case seconds < hour:
		return fmt.Sprintf("%.1f minutes", seconds/minute)
	case seconds < day:
		return fmt.Sprintf("%.1f hours", seconds/hour)
	case seconds < year:
		return fmt.Sprintf("%.1f days", seconds/day)
	case seconds < century:
		return fmt.Sprintf("%.1f years", seconds/year)
	case seconds < millennium:
		return fmt.Sprintf("%.1f centuries", seconds/century)
	case seconds < ageOfUni:
		return fmt.Sprintf("%.1f millennia", seconds/millennium)
	default:
		// Past the age of the universe; report in those units.
		return fmt.Sprintf("%.2g times the age of the universe", seconds/ageOfUni)
	}
}
