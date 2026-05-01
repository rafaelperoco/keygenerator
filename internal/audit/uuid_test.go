package audit

import (
	"bytes"
	"errors"
	"regexp"
	"strings"
	"testing"
)

var uuidV4Re = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestNewUUIDv4_FormatAndBits(t *testing.T) {
	for range 50 {
		s, err := NewUUIDv4(nil)
		if err != nil {
			t.Fatalf("NewUUIDv4: %v", err)
		}
		if !uuidV4Re.MatchString(s) {
			t.Errorf("UUID %q does not match v4 RFC 4122 format", s)
		}
	}
}

func TestNewUUIDv4_DeterministicWithSeededReader(t *testing.T) {
	zeros := bytes.NewReader(make([]byte, 16))
	got, err := NewUUIDv4(zeros)
	if err != nil {
		t.Fatal(err)
	}
	// All-zero entropy with v4 + RFC 4122 bits forced gives a known value:
	// 00000000-0000-4000-8000-000000000000
	want := "00000000-0000-4000-8000-000000000000"
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

type errReader struct{ err error }

func (e errReader) Read(_ []byte) (int, error) { return 0, e.err }

func TestNewUUIDv4_EntropyFailure(t *testing.T) {
	want := errors.New("synthetic")
	_, err := NewUUIDv4(errReader{err: want})
	if err == nil {
		t.Fatal("expected error from failing reader")
	}
	if !strings.Contains(err.Error(), "uuid entropy") {
		t.Errorf("error %q does not mention uuid entropy", err)
	}
}

func TestNewUUIDv4_Uniqueness(t *testing.T) {
	seen := make(map[string]struct{}, 1000)
	for range 1000 {
		s, err := NewUUIDv4(nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, dup := seen[s]; dup {
			t.Fatalf("UUID collision: %s", s)
		}
		seen[s] = struct{}{}
	}
}
