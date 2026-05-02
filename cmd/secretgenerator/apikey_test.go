package main

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func baseAPIKeyOptions(stdout, stderr io.Writer) apiKeyOptions {
	return apiKeyOptions{
		commonOpts: commonOpts{
			stdin:  strings.NewReader(""),
			stdout: stdout,
			stderr: stderr,
			now:    func() time.Time { return time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC) },
			uuid:   func() (string, error) { return "11111111-2222-4333-8444-555555555555", nil },
		},
		Prefix:         "sk",
		Separator:      "_",
		Length:         32,
		MinEntropyBits: 128,
	}
}

func TestRunAPIKey_DefaultsHaveStripeShape(t *testing.T) {
	var stdout, stderr bytes.Buffer
	o := baseAPIKeyOptions(&stdout, &stderr)
	if err := runAPIKey(o); err != nil {
		t.Fatalf("runAPIKey: %v", err)
	}
	got := strings.TrimRight(stdout.String(), "\n")
	if !strings.HasPrefix(got, "sk_") {
		t.Errorf("token %q missing sk_ prefix", got)
	}
	body := strings.TrimPrefix(got, "sk_")
	if len(body) != 32 {
		t.Errorf("body length = %d, want 32", len(body))
	}
	for _, r := range body {
		ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
		if !ok {
			t.Errorf("rune %q not in base62", r)
		}
	}
}

func TestRunAPIKey_JSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	o := baseAPIKeyOptions(&stdout, &stderr)
	o.JSON = true
	if err := runAPIKey(o); err != nil {
		t.Fatalf("runAPIKey: %v", err)
	}
	out := decodeJSON(t, stdout.Bytes())
	if out.Subcommand != "api-key" {
		t.Errorf("subcommand = %q", out.Subcommand)
	}
	if out.CharsetID != "base62-v1" {
		t.Errorf("charset_id = %q", out.CharsetID)
	}
	// 32 chars * log2(62) ≈ 190.5 bits
	if out.EntropyBits < 190 || out.EntropyBits > 191 {
		t.Errorf("entropy_bits = %v, want ~190", out.EntropyBits)
	}
}

func TestRunAPIKey_CustomPrefixAndSeparator(t *testing.T) {
	tests := []struct {
		prefix    string
		separator string
		want      string
	}{
		{"ghp", "_", "ghp_"},
		{"xoxb", "-", "xoxb-"},
		{"sk-ant", "-api-", "sk-ant-api-"},
	}
	for _, tt := range tests {
		t.Run(tt.prefix+tt.separator, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			o := baseAPIKeyOptions(&stdout, &stderr)
			o.Prefix = tt.prefix
			o.Separator = tt.separator
			if err := runAPIKey(o); err != nil {
				t.Fatalf("runAPIKey: %v", err)
			}
			got := strings.TrimRight(stdout.String(), "\n")
			if !strings.HasPrefix(got, tt.want) {
				t.Errorf("token %q missing prefix %q", got, tt.want)
			}
		})
	}
}

func TestRunAPIKey_EmptyPrefix(t *testing.T) {
	var stdout, stderr bytes.Buffer
	o := baseAPIKeyOptions(&stdout, &stderr)
	o.Prefix = ""
	err := runAPIKey(o)
	var ce *codedError
	if !errors.As(err, &ce) || ce.code != ExitInvalidArgs {
		t.Errorf("got %v, want ExitInvalidArgs", err)
	}
}

func TestRunAPIKey_PrefixWithWhitespace(t *testing.T) {
	var stdout, stderr bytes.Buffer
	o := baseAPIKeyOptions(&stdout, &stderr)
	o.Prefix = "sk live"
	err := runAPIKey(o)
	var ce *codedError
	if !errors.As(err, &ce) || ce.code != ExitInvalidArgs {
		t.Errorf("got %v, want ExitInvalidArgs", err)
	}
}

func TestRunAPIKey_LengthZero(t *testing.T) {
	var stdout, stderr bytes.Buffer
	o := baseAPIKeyOptions(&stdout, &stderr)
	o.Length = 0
	err := runAPIKey(o)
	var ce *codedError
	if !errors.As(err, &ce) || ce.code != ExitInvalidArgs {
		t.Errorf("got %v, want ExitInvalidArgs", err)
	}
}

func TestRunAPIKey_EntropyFloor(t *testing.T) {
	var stdout, stderr bytes.Buffer
	o := baseAPIKeyOptions(&stdout, &stderr)
	o.Length = 8 // 8*log2(62) ≈ 47.6 bits, below 128 floor
	err := runAPIKey(o)
	var ce *codedError
	if !errors.As(err, &ce) || ce.code != ExitEntropyTooLow {
		t.Errorf("got %v, want ExitEntropyTooLow", err)
	}
}

func TestRunAPIKey_StdinParams(t *testing.T) {
	var stdout, stderr bytes.Buffer
	o := baseAPIKeyOptions(&stdout, &stderr)
	o.StdinParams = true
	o.stdin = strings.NewReader(`{
		"prefix": "anth",
		"separator": "-",
		"length": 40,
		"min_entropy_bits": 100,
		"allow_weak": false,
		"require_schema_version": 1
	}`)
	o.JSON = true
	if err := runAPIKey(o); err != nil {
		t.Fatalf("runAPIKey: %v", err)
	}
	out := decodeJSON(t, stdout.Bytes())
	if !strings.HasPrefix(out.Password, "anth-") {
		t.Errorf("password %q missing anth- prefix", out.Password)
	}
	if out.Length != 40 {
		t.Errorf("length = %d, want 40", out.Length)
	}
}

func TestRunAPIKey_AllowWeak(t *testing.T) {
	var stdout, stderr bytes.Buffer
	o := baseAPIKeyOptions(&stdout, &stderr)
	o.Length = 8
	o.AllowWeak = true
	o.JSON = true
	if err := runAPIKey(o); err != nil {
		t.Fatalf("runAPIKey: %v", err)
	}
	out := decodeJSON(t, stdout.Bytes())
	if len(out.Warnings) == 0 {
		t.Errorf("expected warning")
	}
}

func TestNewAPIKeyCmd_FlagsRegistered(t *testing.T) {
	cmd := newAPIKeyCmd()
	for _, name := range []string{
		"prefix", "separator", "length",
		"min-entropy-bits", "allow-weak",
		"json", "audit-log", "stdin-params", "require-schema-version",
	} {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("flag %q not registered", name)
		}
	}
}
