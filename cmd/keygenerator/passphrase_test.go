package main

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/rafaelperoco/keygenerator/internal/words"
)

func basePassphraseOptions(stdout, stderr io.Writer) passphraseOptions {
	return passphraseOptions{
		commonOpts: commonOpts{
			stdin:  strings.NewReader(""),
			stdout: stdout,
			stderr: stderr,
			now:    func() time.Time { return time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC) },
			uuid:   func() (string, error) { return "11111111-2222-4333-8444-555555555555", nil },
		},
		Words:          8,
		Separator:      "-",
		MinEntropyBits: 80,
	}
}

func TestRunPassphrase_DefaultIsEightWords(t *testing.T) {
	var stdout, stderr bytes.Buffer
	o := basePassphraseOptions(&stdout, &stderr)
	if err := runPassphrase(o); err != nil {
		t.Fatalf("runPassphrase: %v", err)
	}
	got := strings.TrimRight(stdout.String(), "\n")
	parts := strings.Split(got, "-")
	if len(parts) != 8 {
		t.Errorf("got %d words (%q), want 8", len(parts), got)
	}
}

func TestRunPassphrase_WordsAreFromEFFLarge(t *testing.T) {
	list, _ := words.EFFLarge()
	have := make(map[string]struct{}, len(list))
	for _, w := range list {
		have[w] = struct{}{}
	}
	var stdout, stderr bytes.Buffer
	o := basePassphraseOptions(&stdout, &stderr)
	if err := runPassphrase(o); err != nil {
		t.Fatalf("runPassphrase: %v", err)
	}
	got := strings.TrimRight(stdout.String(), "\n")
	for _, w := range strings.Split(got, "-") {
		if _, ok := have[w]; !ok {
			t.Errorf("word %q not in EFF Large list", w)
		}
	}
}

func TestRunPassphrase_JSONReportsEntropyAndCharsetID(t *testing.T) {
	var stdout, stderr bytes.Buffer
	o := basePassphraseOptions(&stdout, &stderr)
	o.JSON = true
	if err := runPassphrase(o); err != nil {
		t.Fatalf("runPassphrase: %v", err)
	}
	out := decodeJSON(t, stdout.Bytes())
	if out.Subcommand != "passphrase" {
		t.Errorf("subcommand = %q", out.Subcommand)
	}
	if out.CharsetID != "eff-large-v1" {
		t.Errorf("charset_id = %q", out.CharsetID)
	}
	if out.CharsetSize != 7776 {
		t.Errorf("charset_size = %d, want 7776", out.CharsetSize)
	}
	// 8 * log2(7776) ≈ 103.4
	if out.EntropyBits < 103 || out.EntropyBits > 104 {
		t.Errorf("entropy_bits = %v, want ~103.4", out.EntropyBits)
	}
	if out.Algorithm != "diceware/eff-large-v1" {
		t.Errorf("algorithm = %q", out.Algorithm)
	}
}

func TestRunPassphrase_CustomSeparator(t *testing.T) {
	for _, sep := range []string{" ", ".", "_", "/"} {
		t.Run(sep, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			o := basePassphraseOptions(&stdout, &stderr)
			o.Separator = sep
			if err := runPassphrase(o); err != nil {
				t.Fatalf("runPassphrase: %v", err)
			}
			got := strings.TrimRight(stdout.String(), "\n")
			if !strings.Contains(got, sep) {
				t.Errorf("output %q does not contain separator %q", got, sep)
			}
		})
	}
}

func TestRunPassphrase_EmptySeparatorRejected(t *testing.T) {
	var stdout, stderr bytes.Buffer
	o := basePassphraseOptions(&stdout, &stderr)
	o.Separator = ""
	err := runPassphrase(o)
	var ce *codedError
	if !errors.As(err, &ce) || ce.code != ExitInvalidArgs {
		t.Errorf("got %v, want ExitInvalidArgs", err)
	}
}

func TestRunPassphrase_WordsZeroRejected(t *testing.T) {
	var stdout, stderr bytes.Buffer
	o := basePassphraseOptions(&stdout, &stderr)
	o.Words = 0
	err := runPassphrase(o)
	var ce *codedError
	if !errors.As(err, &ce) || ce.code != ExitInvalidArgs {
		t.Errorf("got %v, want ExitInvalidArgs", err)
	}
}

func TestRunPassphrase_EntropyFloor(t *testing.T) {
	var stdout, stderr bytes.Buffer
	o := basePassphraseOptions(&stdout, &stderr)
	o.Words = 5 // 5*12.92 ≈ 64.6 bits, below 80 floor
	err := runPassphrase(o)
	var ce *codedError
	if !errors.As(err, &ce) || ce.code != ExitEntropyTooLow {
		t.Errorf("got %v, want ExitEntropyTooLow", err)
	}
}

func TestRunPassphrase_AllowWeak(t *testing.T) {
	var stdout, stderr bytes.Buffer
	o := basePassphraseOptions(&stdout, &stderr)
	o.Words = 5
	o.AllowWeak = true
	o.JSON = true
	if err := runPassphrase(o); err != nil {
		t.Fatalf("runPassphrase: %v", err)
	}
	out := decodeJSON(t, stdout.Bytes())
	found := false
	for _, w := range out.Warnings {
		if strings.Contains(w, "below floor") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected below-floor warning")
	}
}

func TestRunPassphrase_Capitalize(t *testing.T) {
	var stdout, stderr bytes.Buffer
	o := basePassphraseOptions(&stdout, &stderr)
	o.Capitalize = true
	o.JSON = true
	if err := runPassphrase(o); err != nil {
		t.Fatalf("runPassphrase: %v", err)
	}
	out := decodeJSON(t, stdout.Bytes())
	for _, w := range strings.Split(out.Password, "-") {
		first := w[0]
		if first < 'A' || first > 'Z' {
			t.Errorf("word %q does not start with uppercase", w)
		}
	}
	// must emit a warning that --capitalize is cosmetic
	found := false
	for _, w := range out.Warnings {
		if strings.Contains(w, "Title-Case") || strings.Contains(w, "capitalize") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a capitalize warning, got %v", out.Warnings)
	}
}

func TestRunPassphrase_DigitSuffix(t *testing.T) {
	var stdout, stderr bytes.Buffer
	o := basePassphraseOptions(&stdout, &stderr)
	o.DigitSuffix = true
	o.JSON = true
	if err := runPassphrase(o); err != nil {
		t.Fatalf("runPassphrase: %v", err)
	}
	out := decodeJSON(t, stdout.Bytes())
	last := out.Password[len(out.Password)-1]
	if last < '0' || last > '9' {
		t.Errorf("password %q does not end with a digit", out.Password)
	}
	// entropy should reflect the extra ~3.32 bits
	// 8*log2(7776) + log2(10) ≈ 103.4 + 3.32 ≈ 106.7
	if out.EntropyBits < 106 || out.EntropyBits > 108 {
		t.Errorf("entropy_bits = %v, want ~106.7", out.EntropyBits)
	}
	// must emit warning
	found := false
	for _, w := range out.Warnings {
		if strings.Contains(w, "digit-suffix") || strings.Contains(w, "digit") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected digit-suffix warning, got %v", out.Warnings)
	}
}

func TestRunPassphrase_StdinParams(t *testing.T) {
	var stdout, stderr bytes.Buffer
	o := basePassphraseOptions(&stdout, &stderr)
	o.StdinParams = true
	o.stdin = strings.NewReader(`{
		"words": 10,
		"separator": " ",
		"capitalize": false,
		"digit_suffix": false,
		"min_entropy_bits": 100,
		"allow_weak": false,
		"require_schema_version": 1
	}`)
	o.JSON = true
	if err := runPassphrase(o); err != nil {
		t.Fatalf("runPassphrase: %v", err)
	}
	out := decodeJSON(t, stdout.Bytes())
	if out.Length != 10 {
		t.Errorf("words = %d, want 10", out.Length)
	}
	parts := strings.Split(out.Password, " ")
	if len(parts) != 10 {
		t.Errorf("got %d words, want 10", len(parts))
	}
}

func TestRunPassphrase_StdinParamsBadJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	o := basePassphraseOptions(&stdout, &stderr)
	o.StdinParams = true
	o.stdin = strings.NewReader(`{not valid`)
	err := runPassphrase(o)
	var ce *codedError
	if !errors.As(err, &ce) || ce.code != ExitInvalidArgs {
		t.Errorf("got %v, want ExitInvalidArgs", err)
	}
}

func TestNewPassphraseCmd_FlagsRegistered(t *testing.T) {
	cmd := newPassphraseCmd()
	for _, name := range []string{
		"words", "separator", "capitalize", "digit-suffix",
		"min-entropy-bits", "allow-weak",
		"json", "audit-log", "stdin-params", "require-schema-version",
	} {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("flag %q not registered", name)
		}
	}
}

func TestCapitalizeFirst(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"abacus", "Abacus"},
		{"", ""},
		{"a", "A"},
		{"Already", "Already"}, // already capitalized: unchanged
		{"123word", "123word"}, // doesn't start with letter
	}
	for _, tt := range tests {
		if got := capitalizeFirst(tt.in); got != tt.want {
			t.Errorf("capitalizeFirst(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestPickDigit(t *testing.T) {
	for range 50 {
		d, err := pickDigit()
		if err != nil {
			t.Fatal(err)
		}
		if len(d) != 1 || d[0] < '0' || d[0] > '9' {
			t.Errorf("pickDigit returned %q, want a single digit", d)
		}
	}
}
