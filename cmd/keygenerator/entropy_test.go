package main

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/rafaelperoco/keygenerator/internal/audit"
)

func baseEntropyOptions(stdout, stderr io.Writer) entropyOptions {
	return entropyOptions{
		stdin:  strings.NewReader(""),
		stdout: stdout,
		stderr: stderr,
		now:    func() time.Time { return time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC) },
		uuid:   func() (string, error) { return "11111111-2222-4333-8444-555555555555", nil },
	}
}

func TestRunEntropy_PlainMode(t *testing.T) {
	var stdout, stderr bytes.Buffer
	o := baseEntropyOptions(&stdout, &stderr)
	o.Password = "hello"
	if err := runEntropy(o); err != nil {
		t.Fatalf("runEntropy: %v", err)
	}
	got := strings.TrimRight(stdout.String(), "\n")
	if !strings.HasSuffix(got, "bits") {
		t.Errorf("plain output %q does not end with 'bits'", got)
	}
	if strings.Contains(got, "hello") {
		t.Errorf("plain output leaked password: %s", got)
	}
}

func TestRunEntropy_JSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	o := baseEntropyOptions(&stdout, &stderr)
	o.JSON = true
	o.Password = "Tr0ub4dor&3"
	if err := runEntropy(o); err != nil {
		t.Fatalf("runEntropy: %v", err)
	}
	out := decodeJSON(t, stdout.Bytes())
	if out.Subcommand != "entropy" {
		t.Errorf("subcommand = %q", out.Subcommand)
	}
	if out.Algorithm != "shannon-upper-bound" {
		t.Errorf("algorithm = %q", out.Algorithm)
	}
	if out.Length != 11 {
		t.Errorf("length = %d, want 11", out.Length)
	}
	// Has all 4 classes: lower, upper, digit, symbol
	if out.RequiredClasses != "lower,upper,digit,symbol" {
		t.Errorf("required_classes = %q", out.RequiredClasses)
	}
	// charset size: 26+26+10+32 = 94
	if out.CharsetSize != 94 {
		t.Errorf("charset_size = %d, want 94", out.CharsetSize)
	}
	if out.Password != "" {
		t.Errorf("JSON output should not include plaintext password; got %q", out.Password)
	}
	if out.SchemaVersion != audit.SchemaVersion {
		t.Errorf("schema_version = %d", out.SchemaVersion)
	}
}

func TestRunEntropy_ClassObservation(t *testing.T) {
	tests := []struct {
		password string
		want     string
		size     int
	}{
		{"abc", "lower", 26},
		{"ABC", "upper", 26},
		{"123", "digit", 10},
		{"!@#", "symbol", 32},
		{"abcDEF", "lower,upper", 52},
		{"Abc1", "lower,upper,digit", 62},
		{"Abc1!", "lower,upper,digit,symbol", 94},
	}
	for _, tt := range tests {
		t.Run(tt.password, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			o := baseEntropyOptions(&stdout, &stderr)
			o.JSON = true
			o.Password = tt.password
			if err := runEntropy(o); err != nil {
				t.Fatalf("runEntropy: %v", err)
			}
			out := decodeJSON(t, stdout.Bytes())
			if out.RequiredClasses != tt.want {
				t.Errorf("classes = %q, want %q", out.RequiredClasses, tt.want)
			}
			if out.CharsetSize != tt.size {
				t.Errorf("size = %d, want %d", out.CharsetSize, tt.size)
			}
		})
	}
}

func TestRunEntropy_ReadsStdinWhenNoArg(t *testing.T) {
	var stdout, stderr bytes.Buffer
	o := baseEntropyOptions(&stdout, &stderr)
	o.stdin = strings.NewReader("hello123\n")
	if err := runEntropy(o); err != nil {
		t.Fatalf("runEntropy: %v", err)
	}
	got := strings.TrimRight(stdout.String(), "\n")
	if !strings.HasSuffix(got, "bits") {
		t.Errorf("output %q", got)
	}
}

func TestRunEntropy_ArgvWarning(t *testing.T) {
	var stdout, stderr bytes.Buffer
	o := baseEntropyOptions(&stdout, &stderr)
	o.JSON = true
	o.Password = "fromargv"
	o.FromArg = true
	if err := runEntropy(o); err != nil {
		t.Fatal(err)
	}
	out := decodeJSON(t, stdout.Bytes())
	found := false
	for _, w := range out.Warnings {
		if strings.Contains(w, "argv") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected argv warning, got %v", out.Warnings)
	}
}

func TestRunEntropy_EmptyPassword(t *testing.T) {
	var stdout, stderr bytes.Buffer
	o := baseEntropyOptions(&stdout, &stderr)
	o.stdin = strings.NewReader("")
	err := runEntropy(o)
	var ce *codedError
	if !errors.As(err, &ce) || ce.code != ExitInvalidArgs {
		t.Errorf("got %v, want ExitInvalidArgs", err)
	}
}

func TestRunEntropy_StdinParams(t *testing.T) {
	var stdout, stderr bytes.Buffer
	o := baseEntropyOptions(&stdout, &stderr)
	o.JSON = true
	o.StdinParams = true
	o.stdin = strings.NewReader(`{"password": "Tr0ub4dor&3"}`)
	if err := runEntropy(o); err != nil {
		t.Fatalf("runEntropy: %v", err)
	}
	out := decodeJSON(t, stdout.Bytes())
	if out.Length != 11 {
		t.Errorf("length = %d, want 11", out.Length)
	}
}

func TestRunEntropy_StdinParamsBadJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	o := baseEntropyOptions(&stdout, &stderr)
	o.StdinParams = true
	o.stdin = strings.NewReader(`{not valid`)
	err := runEntropy(o)
	var ce *codedError
	if !errors.As(err, &ce) || ce.code != ExitInvalidArgs {
		t.Errorf("got %v, want ExitInvalidArgs", err)
	}
}

func TestRunEntropy_RequireSchemaVersionMismatch(t *testing.T) {
	var stdout, stderr bytes.Buffer
	o := baseEntropyOptions(&stdout, &stderr)
	o.RequireSchemaVersion = 99
	o.Password = "x"
	err := runEntropy(o)
	var ce *codedError
	if !errors.As(err, &ce) || ce.code != ExitInvalidArgs {
		t.Errorf("got %v, want ExitInvalidArgs", err)
	}
}

func TestNewEntropyCmd_FlagsRegistered(t *testing.T) {
	cmd := newEntropyCmd()
	for _, name := range []string{"json", "stdin-params", "require-schema-version"} {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("flag %q not registered", name)
		}
	}
	// audit-log should NOT be registered for entropy.
	if cmd.Flags().Lookup("audit-log") != nil {
		t.Errorf("audit-log should not be registered for entropy subcommand")
	}
}

func TestObserveClasses(t *testing.T) {
	if got := observeClasses(""); got != 0 {
		t.Errorf("empty string classes = %b, want 0", got)
	}
	if got := classSize(0); got != 0 {
		t.Errorf("classSize(0) = %d, want 0", got)
	}
	if got := inferCharsetID(0); got != "empty" {
		t.Errorf("inferCharsetID(0) = %q", got)
	}
}
