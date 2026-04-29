// Package generator produces random strings from a Charset using a
// caller-supplied entropy source. It is intentionally small and side-effect
// free so it can be unit tested with a deterministic io.Reader.
package generator

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"

	"github.com/rafaelperoco/keygenerator/internal/charset"
)

// ErrClassExhausted is returned when rejection sampling cannot satisfy
// the required-classes constraint within MaxClassRetries attempts.
var ErrClassExhausted = errors.New("generator: could not satisfy required classes")

// ErrEntropyFailure is returned when the entropy source fails mid-generation.
var ErrEntropyFailure = errors.New("generator: entropy source failure")

// MaxClassRetries caps rejection sampling attempts when a class
// requirement is hard to satisfy. The default of 100 is far above any
// realistic need: for a length-12 alphanumeric password requiring all
// 4 classes, the satisfaction probability is ~0.84, so the chance of
// 100 consecutive rejections is on the order of 10^-83.
const MaxClassRetries = 100

// Request describes a single password generation request.
type Request struct {
	Charset charset.Charset
	Length  int
	// RequiredClasses is a bitmask of charset.Class values that the
	// generated string must collectively contain. Zero disables the check.
	// Callers must validate achievability before invoking Generate (use
	// policy.ValidateClassesAchievable).
	RequiredClasses charset.Class
	// Rand is the entropy source. If nil, crypto/rand.Reader is used.
	Rand io.Reader
}

// Generate returns a string of req.Length runes drawn uniformly from
// req.Charset. If RequiredClasses is non-zero, generation uses rejection
// sampling: candidates that do not contain all required classes are
// discarded and resampled. Any error from the entropy source aborts
// generation; this function never returns a partially-generated string
// on error.
func Generate(req Request) (string, error) {
	if req.Length <= 0 {
		return "", fmt.Errorf("generator: length must be > 0, got %d", req.Length)
	}
	if req.Charset.Size() < 2 {
		return "", fmt.Errorf("generator: charset must contain at least 2 runes, got %d", req.Charset.Size())
	}
	src := req.Rand
	if src == nil {
		src = rand.Reader
	}

	if req.RequiredClasses == 0 {
		return generateOnce(req.Charset, req.Length, src)
	}

	for range MaxClassRetries {
		out, err := generateOnce(req.Charset, req.Length, src)
		if err != nil {
			return "", err
		}
		if hasAllClasses(req.Charset, out, req.RequiredClasses) {
			return out, nil
		}
	}
	return "", fmt.Errorf("%w after %d attempts", ErrClassExhausted, MaxClassRetries)
}

func generateOnce(cs charset.Charset, length int, src io.Reader) (string, error) {
	max := big.NewInt(int64(cs.Size()))
	var b strings.Builder
	b.Grow(length)
	for i := range length {
		idx, err := rand.Int(src, max)
		if err != nil {
			return "", fmt.Errorf("%w at position %d: %w", ErrEntropyFailure, i, err)
		}
		b.WriteRune(cs.Runes[idx.Int64()])
	}
	return b.String(), nil
}

func hasAllClasses(cs charset.Charset, s string, required charset.Class) bool {
	var seen charset.Class
	for _, r := range s {
		seen |= cs.ClassOf(r)
		if seen&required == required {
			return true
		}
	}
	return false
}
