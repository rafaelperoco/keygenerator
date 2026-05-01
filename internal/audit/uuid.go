package audit

import (
	"crypto/rand"
	"fmt"
	"io"
)

// NewUUIDv4 returns a random RFC 4122 version-4 UUID string. It reads 16
// bytes from r (defaulting to crypto/rand.Reader when nil) and sets the
// version (4) and variant (RFC 4122) bits. Returns an error if the
// entropy source fails — never returns a partially-random UUID.
func NewUUIDv4(r io.Reader) (string, error) {
	if r == nil {
		r = rand.Reader
	}
	var b [16]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return "", fmt.Errorf("audit: uuid entropy: %w", err)
	}
	// Set version 4 in the high nibble of byte 6.
	b[6] = (b[6] & 0x0f) | 0x40
	// Set variant RFC 4122 in the high two bits of byte 8.
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
