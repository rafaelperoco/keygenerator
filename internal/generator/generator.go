// Package generator produces random strings from a Charset using a
// caller-supplied entropy source. It is intentionally small and side-effect
// free so it can be unit tested with a deterministic io.Reader.
package generator

import (
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"strings"

	"github.com/rafaelperoco/keygenerator/internal/charset"
)

// Request describes a single password generation request.
type Request struct {
	Charset charset.Charset
	Length  int
	// Rand is the entropy source. If nil, crypto/rand.Reader is used.
	Rand io.Reader
}

// Generate returns a string of req.Length runes drawn uniformly from
// req.Charset. Any error from the entropy source aborts generation; this
// function never returns a partially-generated string on error.
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
	max := big.NewInt(int64(req.Charset.Size()))

	var b strings.Builder
	b.Grow(req.Length)
	for i := 0; i < req.Length; i++ {
		idx, err := rand.Int(src, max)
		if err != nil {
			return "", fmt.Errorf("generator: entropy source failed at position %d: %w", i, err)
		}
		b.WriteRune(req.Charset.Runes[idx.Int64()])
	}
	return b.String(), nil
}
