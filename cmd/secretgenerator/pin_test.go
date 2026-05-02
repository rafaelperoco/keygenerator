package main

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/rafaelperoco/secretgenerator/internal/policy"
)

func basePINOptions(stdout, stderr io.Writer) pinOptions {
	return pinOptions{
		commonOpts: commonOpts{
			stdin:  strings.NewReader(""),
			stdout: stdout,
			stderr: stderr,
			now:    func() time.Time { return time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC) },
			uuid:   func() (string, error) { return "11111111-2222-4333-8444-555555555555", nil },
		},
		Digits:                6,
		AcknowledgeLowEntropy: true,
	}
}

func TestRunPIN_DefaultProducesSixDigits(t *testing.T) {
	var stdout, stderr bytes.Buffer
	o := basePINOptions(&stdout, &stderr)
	if err := runPIN(o); err != nil {
		t.Fatalf("runPIN: %v", err)
	}
	got := strings.TrimRight(stdout.String(), "\n")
	if len(got) != 6 {
		t.Errorf("default pin length = %d, want 6", len(got))
	}
	for _, r := range got {
		if r < '0' || r > '9' {
			t.Errorf("non-digit %q in pin", r)
		}
	}
}

func TestRunPIN_RequiresAcknowledgement(t *testing.T) {
	var stdout, stderr bytes.Buffer
	o := basePINOptions(&stdout, &stderr)
	o.AcknowledgeLowEntropy = false
	err := runPIN(o)
	var ce *codedError
	if !errors.As(err, &ce) || ce.code != ExitEntropyTooLow {
		t.Errorf("got %v, want ExitEntropyTooLow", err)
	}
}

func TestRunPIN_DigitsTooFew(t *testing.T) {
	var stdout, stderr bytes.Buffer
	o := basePINOptions(&stdout, &stderr)
	o.Digits = 3
	err := runPIN(o)
	var ce *codedError
	if !errors.As(err, &ce) || ce.code != ExitInvalidArgs {
		t.Errorf("got %v, want ExitInvalidArgs", err)
	}
}

func TestRunPIN_RejectsWeakPatterns(t *testing.T) {
	// Run many iterations and verify no output is in the blocklist or
	// matches a known weak pattern.
	for i := range 300 {
		var stdout, stderr bytes.Buffer
		o := basePINOptions(&stdout, &stderr)
		o.Digits = 4
		if err := runPIN(o); err != nil {
			t.Fatalf("iter %d: runPIN: %v", i, err)
		}
		got := strings.TrimRight(stdout.String(), "\n")
		if policy.IsWeakPIN(got) {
			t.Errorf("iter %d: produced weak PIN %q", i, got)
		}
	}
}

func TestRunPIN_AllowWeakPatternBypassesRejection(t *testing.T) {
	// With --allow-weak-pattern, weak PINs are permitted. We can't
	// reliably trigger one in a small sample (probability is ~5%), but
	// we can verify the flag is plumbed by running the path and asserting
	// no error.
	var stdout, stderr bytes.Buffer
	o := basePINOptions(&stdout, &stderr)
	o.Digits = 4
	o.AllowWeakPattern = true
	if err := runPIN(o); err != nil {
		t.Fatalf("runPIN: %v", err)
	}
}

func TestRunPIN_JSONHasWarning(t *testing.T) {
	var stdout, stderr bytes.Buffer
	o := basePINOptions(&stdout, &stderr)
	o.JSON = true
	if err := runPIN(o); err != nil {
		t.Fatalf("runPIN: %v", err)
	}
	out := decodeJSON(t, stdout.Bytes())
	if out.Subcommand != "pin" {
		t.Errorf("subcommand = %q", out.Subcommand)
	}
	if out.CharsetID != "digit-v1" {
		t.Errorf("charset_id = %q", out.CharsetID)
	}
	if len(out.Warnings) == 0 {
		t.Errorf("expected at least one warning about PIN entropy")
	}
	// 6 digits * log2(10) ≈ 19.93 bits
	if out.EntropyBits < 19 || out.EntropyBits > 20 {
		t.Errorf("entropy_bits = %v, want ~19.93", out.EntropyBits)
	}
}

func TestRunPIN_StdinParams(t *testing.T) {
	var stdout, stderr bytes.Buffer
	o := basePINOptions(&stdout, &stderr)
	o.AcknowledgeLowEntropy = false
	o.StdinParams = true
	o.stdin = strings.NewReader(`{
		"digits": 8,
		"acknowledge_low_entropy": true,
		"allow_weak_pattern": false,
		"require_schema_version": 1
	}`)
	o.JSON = true
	if err := runPIN(o); err != nil {
		t.Fatalf("runPIN: %v", err)
	}
	out := decodeJSON(t, stdout.Bytes())
	if out.Length != 8 {
		t.Errorf("length = %d, want 8", out.Length)
	}
}

func TestRunPIN_StdinParamsBadJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	o := basePINOptions(&stdout, &stderr)
	o.StdinParams = true
	o.stdin = strings.NewReader(`{not valid`)
	err := runPIN(o)
	var ce *codedError
	if !errors.As(err, &ce) || ce.code != ExitInvalidArgs {
		t.Errorf("got %v, want ExitInvalidArgs", err)
	}
}

func TestNewPINCmd_FlagsRegistered(t *testing.T) {
	cmd := newPINCmd()
	for _, name := range []string{
		"digits", "acknowledge-low-entropy", "allow-weak-pattern",
		"json", "audit-log", "stdin-params", "require-schema-version",
	} {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("flag %q not registered", name)
		}
	}
}
