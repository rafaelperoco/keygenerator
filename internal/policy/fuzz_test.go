package policy

import (
	"strings"
	"testing"

	"github.com/rafaelperoco/keygenerator/internal/charset"
)

// FuzzParseClasses verifies the class parser never panics on arbitrary
// input and that all returned bits correspond to known classes.
func FuzzParseClasses(f *testing.F) {
	f.Add("")
	f.Add("lower")
	f.Add("lower,upper,digit,symbol")
	f.Add(",,,,")
	f.Add("LOWER")
	f.Add("lower,unknown")
	f.Add(strings.Repeat("lower,", 10))
	f.Add("\x00")
	f.Add("\u200b")

	f.Fuzz(func(t *testing.T, spec string) {
		got, err := ParseClasses(spec)
		if err != nil {
			// Error path: result should be zero.
			if got != 0 {
				t.Errorf("ParseClasses err=%v but got=%b (want 0)", err, got)
			}
			return
		}
		// Success: every set bit must be a known class.
		known := charset.ClassLower | charset.ClassUpper | charset.ClassDigit | charset.ClassSymbol
		if got&^known != 0 {
			t.Errorf("ParseClasses returned unknown class bits: %b", got)
		}
	})
}

// FuzzIsWeakPIN verifies the weak-pin classifier is total (no panics)
// and respects the contract: non-digit input → false.
func FuzzIsWeakPIN(f *testing.F) {
	f.Add("")
	f.Add("0000")
	f.Add("1234")
	f.Add("123456789")
	f.Add("abcd")
	f.Add("12a4")
	f.Add("\x00")
	f.Add("9876543210")
	f.Add(strings.Repeat("1", 100))

	f.Fuzz(func(t *testing.T, pin string) {
		got := IsWeakPIN(pin)
		// Contract: any rune outside 0-9 → must return false.
		hasNonDigit := false
		for _, r := range pin {
			if r < '0' || r > '9' {
				hasNonDigit = true
				break
			}
		}
		if hasNonDigit && got {
			// Empty string is the one allowed exception (returns true).
			if pin != "" {
				t.Errorf("IsWeakPIN(%q) = true, but contains non-digit", pin)
			}
		}
	})
}
