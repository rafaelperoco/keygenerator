package main

import (
	"bytes"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rafaelperoco/keygenerator/internal/audit"
)

func baseSecretOptions(stdout, stderr io.Writer) secretOptions {
	return secretOptions{
		commonOpts: commonOpts{
			stdin:  strings.NewReader(""),
			stdout: stdout,
			stderr: stderr,
			now:    func() time.Time { return time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC) },
			uuid:   func() (string, error) { return "11111111-2222-4333-8444-555555555555", nil },
		},
		Bytes:          32,
		Encoding:       "base64url",
		MinEntropyBits: 128,
	}
}

func TestRunSecret_Defaults(t *testing.T) {
	var stdout, stderr bytes.Buffer
	o := baseSecretOptions(&stdout, &stderr)
	if err := runSecret(o); err != nil {
		t.Fatalf("runSecret: %v", err)
	}
	got := strings.TrimRight(stdout.String(), "\n")
	// 32 bytes -> base64url no padding -> ceil(32 * 8 / 6) = 43 chars
	if len(got) != 43 {
		t.Errorf("default secret length = %d, want 43 (32 bytes base64url no padding)", len(got))
	}
	// base64url alphabet
	for _, r := range got {
		ok := (r >= 'A' && r <= 'Z') ||
			(r >= 'a' && r <= 'z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_'
		if !ok {
			t.Errorf("rune %q not in base64url alphabet", r)
		}
	}
}

func TestRunSecret_JSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	o := baseSecretOptions(&stdout, &stderr)
	o.JSON = true
	if err := runSecret(o); err != nil {
		t.Fatalf("runSecret: %v", err)
	}
	out := decodeJSON(t, stdout.Bytes())
	if out.Subcommand != "secret" {
		t.Errorf("subcommand = %q, want secret", out.Subcommand)
	}
	if out.EntropyBits != 256 {
		t.Errorf("entropy_bits = %v, want 256 (32 bytes * 8)", out.EntropyBits)
	}
	if out.CharsetID != "secret-bytes:base64url" {
		t.Errorf("charset_id = %q", out.CharsetID)
	}
	if out.Algorithm != "crypto/rand:bytes+base64url" {
		t.Errorf("algorithm = %q", out.Algorithm)
	}
	if out.SchemaVersion != audit.SchemaVersion {
		t.Errorf("schema_version = %d", out.SchemaVersion)
	}
}

func TestRunSecret_AllEncodings(t *testing.T) {
	tests := []struct {
		encoding   string
		bytes      int
		validateFn func(t *testing.T, s string, raw int)
	}{
		{"base64url", 32, func(t *testing.T, s string, _ int) {
			if _, err := base64.RawURLEncoding.DecodeString(s); err != nil {
				t.Errorf("not valid base64url: %v", err)
			}
		}},
		{"base64", 32, func(t *testing.T, s string, _ int) {
			if _, err := base64.StdEncoding.DecodeString(s); err != nil {
				t.Errorf("not valid base64: %v", err)
			}
		}},
		{"base32", 30, func(t *testing.T, s string, _ int) {
			if _, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s); err != nil {
				t.Errorf("not valid base32: %v", err)
			}
		}},
		{"hex", 16, func(t *testing.T, s string, n int) {
			if got := len(s); got != n*2 {
				t.Errorf("hex length = %d, want %d", got, n*2)
			}
			if _, err := hex.DecodeString(s); err != nil {
				t.Errorf("not valid hex: %v", err)
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.encoding, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			o := baseSecretOptions(&stdout, &stderr)
			o.Encoding = tt.encoding
			o.Bytes = tt.bytes
			o.MinEntropyBits = 0 // disable for narrower tests
			if err := runSecret(o); err != nil {
				t.Fatalf("runSecret: %v", err)
			}
			got := strings.TrimRight(stdout.String(), "\n")
			tt.validateFn(t, got, tt.bytes)
		})
	}
}

func TestRunSecret_Prefix(t *testing.T) {
	var stdout, stderr bytes.Buffer
	o := baseSecretOptions(&stdout, &stderr)
	o.Prefix = "sk_"
	o.JSON = true
	if err := runSecret(o); err != nil {
		t.Fatalf("runSecret: %v", err)
	}
	out := decodeJSON(t, stdout.Bytes())
	if !strings.HasPrefix(out.Password, "sk_") {
		t.Errorf("password %q does not have prefix", out.Password)
	}
	if out.EntropyBits != 256 {
		t.Errorf("entropy_bits should not include prefix: %v", out.EntropyBits)
	}
}

func TestRunSecret_BytesZeroErrors(t *testing.T) {
	var stdout, stderr bytes.Buffer
	o := baseSecretOptions(&stdout, &stderr)
	o.Bytes = 0
	err := runSecret(o)
	var ce *codedError
	if !errors.As(err, &ce) || ce.code != ExitInvalidArgs {
		t.Errorf("got %v, want ExitInvalidArgs", err)
	}
}

func TestRunSecret_UnknownEncoding(t *testing.T) {
	var stdout, stderr bytes.Buffer
	o := baseSecretOptions(&stdout, &stderr)
	o.Encoding = "rot13"
	err := runSecret(o)
	var ce *codedError
	if !errors.As(err, &ce) || ce.code != ExitInvalidArgs {
		t.Errorf("got %v, want ExitInvalidArgs", err)
	}
}

func TestRunSecret_EntropyFloor(t *testing.T) {
	var stdout, stderr bytes.Buffer
	o := baseSecretOptions(&stdout, &stderr)
	o.Bytes = 4 // 32 bits, well below default 128 floor
	err := runSecret(o)
	var ce *codedError
	if !errors.As(err, &ce) || ce.code != ExitEntropyTooLow {
		t.Errorf("got %v, want ExitEntropyTooLow", err)
	}
}

func TestRunSecret_AllowWeakBypassesFloor(t *testing.T) {
	var stdout, stderr bytes.Buffer
	o := baseSecretOptions(&stdout, &stderr)
	o.Bytes = 4
	o.AllowWeak = true
	o.JSON = true
	if err := runSecret(o); err != nil {
		t.Fatalf("runSecret: %v", err)
	}
	out := decodeJSON(t, stdout.Bytes())
	if len(out.Warnings) == 0 {
		t.Errorf("expected warning")
	}
}

func TestRunSecret_StdinParams(t *testing.T) {
	var stdout, stderr bytes.Buffer
	o := baseSecretOptions(&stdout, &stderr)
	o.StdinParams = true
	o.stdin = strings.NewReader(`{
		"bytes": 16,
		"encoding": "hex",
		"prefix": "test_",
		"min_entropy_bits": 64,
		"allow_weak": false,
		"require_schema_version": 1
	}`)
	o.JSON = true
	if err := runSecret(o); err != nil {
		t.Fatalf("runSecret: %v", err)
	}
	out := decodeJSON(t, stdout.Bytes())
	if !strings.HasPrefix(out.Password, "test_") {
		t.Errorf("password %q has no test_ prefix", out.Password)
	}
	hexPart := strings.TrimPrefix(out.Password, "test_")
	if len(hexPart) != 32 {
		t.Errorf("hex part length = %d, want 32 (16 bytes)", len(hexPart))
	}
	if out.EntropyBits != 128 {
		t.Errorf("entropy_bits = %v, want 128 (16*8)", out.EntropyBits)
	}
}

func TestRunSecret_StdinParamsBadJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	o := baseSecretOptions(&stdout, &stderr)
	o.StdinParams = true
	o.stdin = strings.NewReader(`{not json`)
	err := runSecret(o)
	var ce *codedError
	if !errors.As(err, &ce) || ce.code != ExitInvalidArgs {
		t.Errorf("got %v, want ExitInvalidArgs", err)
	}
}

func TestRunSecret_AuditLog(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "secret.jsonl")
	var stdout, stderr bytes.Buffer
	o := baseSecretOptions(&stdout, &stderr)
	o.AuditLogPath = logPath
	o.JSON = true
	if err := runSecret(o); err != nil {
		t.Fatalf("runSecret: %v", err)
	}
	out := decodeJSON(t, stdout.Bytes())
	if out.Password == "" {
		t.Fatal("empty password")
	}
}

func TestRunSecret_Uniqueness(t *testing.T) {
	seen := make(map[string]struct{}, 200)
	for range 200 {
		var stdout, stderr bytes.Buffer
		o := baseSecretOptions(&stdout, &stderr)
		o.Bytes = 16
		o.MinEntropyBits = 0
		if err := runSecret(o); err != nil {
			t.Fatal(err)
		}
		got := strings.TrimRight(stdout.String(), "\n")
		if _, dup := seen[got]; dup {
			t.Fatalf("duplicate secret: %s", got)
		}
		seen[got] = struct{}{}
	}
}

func TestNewSecretCmd_FlagsRegistered(t *testing.T) {
	cmd := newSecretCmd()
	for _, name := range []string{
		"bytes", "encoding", "prefix",
		"min-entropy-bits", "allow-weak",
		"json", "audit-log", "stdin-params", "require-schema-version",
	} {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("flag %q not registered on secret cmd", name)
		}
	}
}

func TestZeroize(t *testing.T) {
	b := []byte{1, 2, 3, 4, 5}
	zeroize(b)
	for i, v := range b {
		if v != 0 {
			t.Errorf("b[%d] = %d, want 0", i, v)
		}
	}
	zeroize(nil) // must not panic
	zeroize([]byte{})
}

func TestEncode_PanicsOnInvalid(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on invalid encoding")
		}
	}()
	encode([]byte{1, 2, 3}, "invalid-encoding")
}
