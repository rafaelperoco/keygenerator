// Package charset defines named, versioned character sets used by the
// password generator. IDs (e.g. "alphanum-v1") are part of the audit
// contract: changing the runes behind an existing ID is a breaking change
// and requires bumping the version suffix.
package charset

import (
	"fmt"
	"slices"
)

// Class identifies a character category for class-requirement enforcement.
type Class uint8

// Class bitmask values. Combine with bitwise OR to express a set of
// classes (e.g. ClassLower|ClassUpper). Used by --require-classes.
const (
	ClassLower Class = 1 << iota
	ClassUpper
	ClassDigit
	ClassSymbol
)

// Charset is an immutable, named set of runes drawn from one or more classes.
type Charset struct {
	ID      string
	Runes   []rune
	Classes Class
}

// Size returns the number of runes in the charset.
func (c Charset) Size() int { return len(c.Runes) }

// Contains reports whether r is part of the charset.
func (c Charset) Contains(r rune) bool {
	return slices.Contains(c.Runes, r)
}

// ClassOf returns the class bitmask for r within this charset, or 0 if r is
// not present.
func (c Charset) ClassOf(r rune) Class {
	if !slices.Contains(c.Runes, r) {
		return 0
	}
	return classOfRune(r)
}

func classOfRune(r rune) Class {
	switch {
	case r >= 'a' && r <= 'z':
		return ClassLower
	case r >= 'A' && r <= 'Z':
		return ClassUpper
	case r >= '0' && r <= '9':
		return ClassDigit
	default:
		return ClassSymbol
	}
}

// Get returns the charset registered under id, or an error if unknown.
func Get(id string) (Charset, error) {
	c, ok := registry[id]
	if !ok {
		return Charset{}, fmt.Errorf("charset: unknown id %q", id)
	}
	return c, nil
}

// Exclude returns a new Charset with the given runes removed. The returned
// Charset preserves the source ID suffixed with a deterministic exclusion
// marker so audit logs can distinguish derived charsets. Returns an error if
// the resulting set has fewer than 2 runes.
func Exclude(c Charset, exclude []rune) (Charset, error) {
	if len(exclude) == 0 {
		return c, nil
	}
	skip := make(map[rune]struct{}, len(exclude))
	for _, r := range exclude {
		skip[r] = struct{}{}
	}
	out := make([]rune, 0, len(c.Runes))
	var classes Class
	for _, r := range c.Runes {
		if _, drop := skip[r]; drop {
			continue
		}
		out = append(out, r)
		classes |= classOfRune(r)
	}
	if len(out) < 2 {
		return Charset{}, fmt.Errorf("charset: exclusion left %d runes (minimum 2)", len(out))
	}
	return Charset{
		ID:      c.ID + "+excluded",
		Runes:   out,
		Classes: classes,
	}, nil
}
