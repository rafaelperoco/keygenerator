package words

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func TestEFFLarge_Count(t *testing.T) {
	list, err := EFFLarge()
	if err != nil {
		t.Fatalf("EFFLarge: %v", err)
	}
	if len(list) != EFFLargeWordCount {
		t.Errorf("len = %d, want %d", len(list), EFFLargeWordCount)
	}
}

func TestEFFLarge_NoEmptyOrDupes(t *testing.T) {
	list, _ := EFFLarge()
	seen := make(map[string]struct{}, len(list))
	for i, w := range list {
		if w == "" {
			t.Errorf("empty word at index %d", i)
		}
		if _, dup := seen[w]; dup {
			t.Errorf("duplicate word %q at index %d", w, i)
		}
		seen[w] = struct{}{}
	}
}

func TestEFFLarge_KnownWords(t *testing.T) {
	list, _ := EFFLarge()
	// Spot-check that famous EFF list words exist.
	want := []string{"abacus", "trombone", "zoom", "yearling", "absentee"}
	have := make(map[string]struct{}, len(list))
	for _, w := range list {
		have[w] = struct{}{}
	}
	for _, w := range want {
		if _, ok := have[w]; !ok {
			t.Errorf("expected word %q not in list", w)
		}
	}
}

func TestEFFLarge_SHA256(t *testing.T) {
	sum := sha256.Sum256([]byte(rawEFFLarge))
	got := hex.EncodeToString(sum[:])
	if got != EFFLargeSHA256 {
		t.Errorf("embedded wordlist SHA-256 = %s, want %s", got, EFFLargeSHA256)
	}
}

func TestPickEFFLarge_LengthAndMembership(t *testing.T) {
	list, _ := EFFLarge()
	have := make(map[string]struct{}, len(list))
	for _, w := range list {
		have[w] = struct{}{}
	}

	picked, err := PickEFFLarge(8, nil)
	if err != nil {
		t.Fatalf("PickEFFLarge: %v", err)
	}
	if len(picked) != 8 {
		t.Errorf("len = %d, want 8", len(picked))
	}
	for _, w := range picked {
		if _, ok := have[w]; !ok {
			t.Errorf("picked word %q not in list", w)
		}
	}
}

func TestPickEFFLarge_NLessThanOne(t *testing.T) {
	if _, err := PickEFFLarge(0, nil); err == nil {
		t.Error("PickEFFLarge(0) returned nil error")
	}
	if _, err := PickEFFLarge(-3, nil); err == nil {
		t.Error("PickEFFLarge(-3) returned nil error")
	}
}

type errReader struct{ err error }

func (e errReader) Read(_ []byte) (int, error) { return 0, e.err }

func TestPickEFFLarge_ReaderError(t *testing.T) {
	want := errors.New("synthetic")
	_, err := PickEFFLarge(5, errReader{err: want})
	if err == nil {
		t.Fatal("nil error")
	}
	if !strings.Contains(err.Error(), "entropy source failed") {
		t.Errorf("err = %q", err)
	}
}

func TestPickEFFLarge_ReaderEOF(t *testing.T) {
	_, err := PickEFFLarge(5, bytes.NewReader([]byte{}))
	if err == nil {
		t.Fatal("expected EOF-related error")
	}
}

func TestEFFLarge_BitsPerWordConstant(t *testing.T) {
	// log2(7776) ≈ 12.9248
	want := 12.9248
	if EFFLargeBitsPerWord < want-0.001 || EFFLargeBitsPerWord > want+0.001 {
		t.Errorf("EFFLargeBitsPerWord = %v, want ~%v", EFFLargeBitsPerWord, want)
	}
}
