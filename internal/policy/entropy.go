// Package policy enforces strength policies on password requests:
// minimum entropy, character-class requirements, and entropy computation.
package policy

import (
	"errors"
	"fmt"
	"math"

	"github.com/rafaelperoco/secretgenerator/internal/charset"
)

// ErrBelowEntropyFloor is returned when computed entropy is below the
// configured floor and AllowWeak is false.
var ErrBelowEntropyFloor = errors.New("policy: entropy below floor")

// ErrClassesImpossible is returned when the request asks for more distinct
// classes than the charset can supply, or asks for classes the charset
// does not contain at all.
var ErrClassesImpossible = errors.New("policy: required classes cannot be satisfied by charset")

// EntropyBits returns the Shannon entropy in bits of a uniformly random
// string of the given length drawn from a charset of charsetSize runes:
// length * log2(charsetSize). Returns 0 for empty inputs.
func EntropyBits(length, charsetSize int) float64 {
	if length <= 0 || charsetSize <= 1 {
		return 0
	}
	return float64(length) * math.Log2(float64(charsetSize))
}

// EnforceFloor returns ErrBelowEntropyFloor when bits < floor and allowWeak
// is false. floor <= 0 disables the check.
func EnforceFloor(bits, floor float64, allowWeak bool) error {
	if floor <= 0 {
		return nil
	}
	if bits >= floor {
		return nil
	}
	if allowWeak {
		return nil
	}
	return fmt.Errorf("%w: %.2f bits < floor %.2f", ErrBelowEntropyFloor, bits, floor)
}

// ValidateClassesAchievable checks that every required class is supported
// by the charset and that the request length is at least the number of
// required classes (otherwise no string can ever satisfy the requirements).
func ValidateClassesAchievable(cs charset.Charset, length int, required charset.Class) error {
	if required == 0 {
		return nil
	}
	missing := required &^ cs.Classes
	if missing != 0 {
		return fmt.Errorf("%w: charset %q does not contain classes %s",
			ErrClassesImpossible, cs.ID, classNames(missing))
	}
	if popcount(uint8(required)) > length {
		return fmt.Errorf("%w: %d distinct classes required but length is %d",
			ErrClassesImpossible, popcount(uint8(required)), length)
	}
	return nil
}

// ParseClasses parses a comma-separated list of class names (lower, upper,
// digit, symbol) into a Class bitmask. Empty input returns 0.
func ParseClasses(spec string) (charset.Class, error) {
	if spec == "" {
		return 0, nil
	}
	var out charset.Class
	for _, name := range splitCSV(spec) {
		switch name {
		case "lower":
			out |= charset.ClassLower
		case "upper":
			out |= charset.ClassUpper
		case "digit":
			out |= charset.ClassDigit
		case "symbol":
			out |= charset.ClassSymbol
		default:
			return 0, fmt.Errorf("policy: unknown class %q (want lower|upper|digit|symbol)", name)
		}
	}
	return out, nil
}

// ClassesString renders a Class bitmask as a stable comma-separated list
// in canonical order: lower,upper,digit,symbol.
func ClassesString(c charset.Class) string {
	return classNames(c)
}

func classNames(c charset.Class) string {
	parts := make([]string, 0, 4)
	if c&charset.ClassLower != 0 {
		parts = append(parts, "lower")
	}
	if c&charset.ClassUpper != 0 {
		parts = append(parts, "upper")
	}
	if c&charset.ClassDigit != 0 {
		parts = append(parts, "digit")
	}
	if c&charset.ClassSymbol != 0 {
		parts = append(parts, "symbol")
	}
	return joinCSV(parts)
}

func popcount(b uint8) int {
	n := 0
	for b != 0 {
		n += int(b & 1)
		b >>= 1
	}
	return n
}

func splitCSV(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			if i > start {
				out = append(out, s[start:i])
			}
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

func joinCSV(parts []string) string {
	if len(parts) == 0 {
		return ""
	}
	out := parts[0]
	for _, p := range parts[1:] {
		out += "," + p
	}
	return out
}
