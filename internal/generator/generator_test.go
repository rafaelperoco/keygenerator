package generator

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/rafaelperoco/keygenerator/internal/charset"
)

type errReader struct{ err error }

func (e errReader) Read(_ []byte) (int, error) { return 0, e.err }

func TestGenerate_LengthExact(t *testing.T) {
	cs, _ := charset.Get("alphanum-v1")
	for _, n := range []int{1, 5, 20, 64, 256} {
		out, err := Generate(Request{Charset: cs, Length: n})
		if err != nil {
			t.Fatalf("Generate(n=%d) error: %v", n, err)
		}
		if got := len([]rune(out)); got != n {
			t.Errorf("Generate(n=%d) produced %d runes, want %d", n, got, n)
		}
	}
}

func TestGenerate_AllRunesInCharset(t *testing.T) {
	for _, id := range charset.IDs() {
		t.Run(id, func(t *testing.T) {
			cs, _ := charset.Get(id)
			out, err := Generate(Request{Charset: cs, Length: 200})
			if err != nil {
				t.Fatalf("Generate error: %v", err)
			}
			for _, r := range out {
				if !cs.Contains(r) {
					t.Errorf("rune %q not in charset %q", r, id)
				}
			}
		})
	}
}

func TestGenerate_RNGFailureAborts(t *testing.T) {
	cs, _ := charset.Get("alphanum-v1")
	want := errors.New("synthetic rng failure")
	_, err := Generate(Request{
		Charset: cs,
		Length:  20,
		Rand:    errReader{err: want},
	})
	if err == nil {
		t.Fatal("Generate with failing reader returned nil error")
	}
	if !strings.Contains(err.Error(), "entropy source failed") {
		t.Errorf("error = %q, want it to mention 'entropy source failed'", err)
	}
}

func TestGenerate_LengthZeroErrors(t *testing.T) {
	cs, _ := charset.Get("alphanum-v1")
	if _, err := Generate(Request{Charset: cs, Length: 0}); err == nil {
		t.Fatal("Generate(length=0) returned nil error")
	}
	if _, err := Generate(Request{Charset: cs, Length: -1}); err == nil {
		t.Fatal("Generate(length=-1) returned nil error")
	}
}

func TestGenerate_TinyCharsetErrors(t *testing.T) {
	tiny := charset.Charset{ID: "tiny", Runes: []rune("a"), Classes: charset.ClassLower}
	if _, err := Generate(Request{Charset: tiny, Length: 5}); err == nil {
		t.Fatal("Generate with single-rune charset returned nil error")
	}
}

func TestGenerate_DefaultsToCryptoRand(t *testing.T) {
	cs, _ := charset.Get("alphanum-v1")
	out, err := Generate(Request{Charset: cs, Length: 20, Rand: nil})
	if err != nil {
		t.Fatalf("Generate(nil reader) error: %v", err)
	}
	if len([]rune(out)) != 20 {
		t.Errorf("default reader produced wrong length: %d", len([]rune(out)))
	}
}

// TestGenerate_DeterministicWithSeededReader verifies the function is
// deterministic when given a deterministic byte source. crypto/rand.Int reads
// from the supplied reader, so a fixed buffer yields a fixed sequence.
func TestGenerate_DeterministicWithSeededReader(t *testing.T) {
	cs, _ := charset.Get("hex-v1")
	seed := bytes.Repeat([]byte{0x42}, 1024)
	a, err := Generate(Request{Charset: cs, Length: 32, Rand: bytes.NewReader(seed)})
	if err != nil {
		t.Fatalf("Generate a: %v", err)
	}
	b, err := Generate(Request{Charset: cs, Length: 32, Rand: bytes.NewReader(seed)})
	if err != nil {
		t.Fatalf("Generate b: %v", err)
	}
	if a != b {
		t.Errorf("seeded Generate not deterministic: %q vs %q", a, b)
	}
}

// TestGenerate_ReaderEOFAborts ensures truncated entropy aborts cleanly
// rather than producing a partial password.
func TestGenerate_ReaderEOFAborts(t *testing.T) {
	cs, _ := charset.Get("alphanum-v1")
	_, err := Generate(Request{
		Charset: cs,
		Length:  100,
		Rand:    bytes.NewReader([]byte{}),
	})
	if err == nil {
		t.Fatal("Generate with empty reader returned nil error")
	}
	if !errors.Is(err, io.ErrUnexpectedEOF) && !strings.Contains(err.Error(), "EOF") {
		t.Errorf("error = %v, want EOF-related", err)
	}
}
