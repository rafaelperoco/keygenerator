package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rafaelperoco/keygenerator/internal/audit"
)

func baseOptions(stdout, stderr io.Writer) runOptions {
	return runOptions{
		commonOpts: commonOpts{
			stdin:  strings.NewReader(""),
			stdout: stdout,
			stderr: stderr,
			now:    func() time.Time { return time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC) },
			uuid:   func() (string, error) { return "11111111-2222-4333-8444-555555555555", nil },
		},
		Length:         20,
		CharsetID:      "alphanum-v1",
		MinEntropyBits: 80,
	}
}

func decodeJSON(t *testing.T, b []byte) audit.Output {
	t.Helper()
	var out audit.Output
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("json: %v\n%s", err, b)
	}
	return out
}

func TestRunPassword_PlaintextDefault(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := runPassword(baseOptions(&stdout, &stderr)); err != nil {
		t.Fatalf("runPassword: %v", err)
	}
	got := strings.TrimRight(stdout.String(), "\n")
	if len([]rune(got)) != 20 {
		t.Errorf("password length = %d, want 20", len([]rune(got)))
	}
}

func TestRunPassword_JSONOutput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	o := baseOptions(&stdout, &stderr)
	o.JSON = true
	if err := runPassword(o); err != nil {
		t.Fatalf("runPassword: %v", err)
	}
	out := decodeJSON(t, stdout.Bytes())
	if out.SchemaVersion != audit.SchemaVersion {
		t.Errorf("schema_version = %d, want %d", out.SchemaVersion, audit.SchemaVersion)
	}
	if out.Length != 20 {
		t.Errorf("length = %d, want 20", out.Length)
	}
	if out.CharsetID != "alphanum-v1" {
		t.Errorf("charset_id = %q, want alphanum-v1", out.CharsetID)
	}
	if out.CharsetSize != 62 {
		t.Errorf("charset_size = %d, want 62", out.CharsetSize)
	}
	if out.EntropyBits < 119 || out.EntropyBits > 120 {
		t.Errorf("entropy_bits = %v, want ~119.08", out.EntropyBits)
	}
	if out.Algorithm != "crypto/rand+rejection-sampling" {
		t.Errorf("algorithm = %q", out.Algorithm)
	}
	if out.Subcommand != "password" {
		t.Errorf("subcommand = %q", out.Subcommand)
	}
	if out.RequestID != "11111111-2222-4333-8444-555555555555" {
		t.Errorf("request_id = %q", out.RequestID)
	}
	if out.TimestampUTC != "2025-01-01T00:00:00Z" {
		t.Errorf("timestamp_utc = %q", out.TimestampUTC)
	}
	if len([]rune(out.Password)) != 20 {
		t.Errorf("password length in JSON = %d, want 20", len([]rune(out.Password)))
	}
}

func TestRunPassword_ExcludeShrinksCharsetButKeepsLength(t *testing.T) {
	var stdout, stderr bytes.Buffer
	o := baseOptions(&stdout, &stderr)
	o.JSON = true
	o.Exclude = "abcdefghij" // 10 chars removed
	if err := runPassword(o); err != nil {
		t.Fatalf("runPassword: %v", err)
	}
	out := decodeJSON(t, stdout.Bytes())
	if out.Length != 20 {
		t.Errorf("length = %d, want 20", out.Length)
	}
	if out.CharsetSize != 52 {
		t.Errorf("charset_size = %d, want 52 (62-10)", out.CharsetSize)
	}
	if len([]rune(out.Password)) != 20 {
		t.Errorf("password length = %d, want 20 (v1 bug fixed)", len([]rune(out.Password)))
	}
	for _, r := range out.Password {
		if strings.ContainsRune(o.Exclude, r) {
			t.Errorf("password %q contains excluded rune %q", out.Password, r)
		}
	}
	if out.ExcludedCount != 10 {
		t.Errorf("excluded_count = %d, want 10", out.ExcludedCount)
	}
	if out.ExcludedSHA256 == "" {
		t.Errorf("excluded_sha256 should be populated")
	}
}

func TestRunPassword_ExcludeEmptyingCharsetReturnsCharsetEmpty(t *testing.T) {
	var stdout, stderr bytes.Buffer
	o := baseOptions(&stdout, &stderr)
	o.CharsetID = "digit-v1"
	o.Exclude = "0123456789"
	o.MinEntropyBits = 0
	err := runPassword(o)
	if err == nil {
		t.Fatal("expected error")
	}
	var ce *codedError
	if !errors.As(err, &ce) || ce.code != ExitCharsetEmpty {
		t.Errorf("got code=%v err=%v, want ExitCharsetEmpty(%d)", ce, err, ExitCharsetEmpty)
	}
}

func TestRunPassword_EntropyFloor(t *testing.T) {
	var stdout, stderr bytes.Buffer
	o := baseOptions(&stdout, &stderr)
	o.Length = 4 // 4*log2(62) ≈ 23.8 bits
	err := runPassword(o)
	var ce *codedError
	if !errors.As(err, &ce) || ce.code != ExitEntropyTooLow {
		t.Errorf("got %v, want ExitEntropyTooLow", err)
	}
}

func TestRunPassword_AllowWeakBypassesFloorWithWarning(t *testing.T) {
	var stdout, stderr bytes.Buffer
	o := baseOptions(&stdout, &stderr)
	o.Length = 4
	o.AllowWeak = true
	o.JSON = true
	if err := runPassword(o); err != nil {
		t.Fatalf("runPassword: %v", err)
	}
	out := decodeJSON(t, stdout.Bytes())
	if len(out.Warnings) == 0 {
		t.Errorf("expected warning, got none")
	}
	if out.Length != 4 {
		t.Errorf("length = %d, want 4", out.Length)
	}
}

func TestRunPassword_RequiredClassesAllPresent(t *testing.T) {
	var stdout, stderr bytes.Buffer
	o := baseOptions(&stdout, &stderr)
	o.CharsetID = "alphanum-symbols-v1"
	o.RequiredClassesSpec = "lower,upper,digit,symbol"
	o.JSON = true
	if err := runPassword(o); err != nil {
		t.Fatalf("runPassword: %v", err)
	}
	out := decodeJSON(t, stdout.Bytes())
	hasLower, hasUpper, hasDigit, hasSymbol := false, false, false, false
	for _, r := range out.Password {
		switch {
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= '0' && r <= '9':
			hasDigit = true
		default:
			hasSymbol = true
		}
	}
	if !hasLower || !hasUpper || !hasDigit || !hasSymbol {
		t.Errorf("classes missing in %q: lower=%v upper=%v digit=%v symbol=%v",
			out.Password, hasLower, hasUpper, hasDigit, hasSymbol)
	}
	if out.RequiredClasses != "lower,upper,digit,symbol" {
		t.Errorf("required_classes = %q", out.RequiredClasses)
	}
}

func TestRunPassword_RequiredClassesImpossible(t *testing.T) {
	var stdout, stderr bytes.Buffer
	o := baseOptions(&stdout, &stderr)
	o.CharsetID = "digit-v1"
	o.RequiredClassesSpec = "symbol"
	o.MinEntropyBits = 0
	err := runPassword(o)
	var ce *codedError
	if !errors.As(err, &ce) || ce.code != ExitClassImpossible {
		t.Errorf("got %v, want ExitClassImpossible", err)
	}
}

func TestRunPassword_RequiredClassesUnknownName(t *testing.T) {
	var stdout, stderr bytes.Buffer
	o := baseOptions(&stdout, &stderr)
	o.RequiredClassesSpec = "bogus"
	err := runPassword(o)
	var ce *codedError
	if !errors.As(err, &ce) || ce.code != ExitInvalidArgs {
		t.Errorf("got %v, want ExitInvalidArgs", err)
	}
}

func TestRunPassword_UnknownCharset(t *testing.T) {
	var stdout, stderr bytes.Buffer
	o := baseOptions(&stdout, &stderr)
	o.CharsetID = "no-such-charset"
	err := runPassword(o)
	var ce *codedError
	if !errors.As(err, &ce) || ce.code != ExitInvalidArgs {
		t.Errorf("got %v, want ExitInvalidArgs", err)
	}
}

func TestRunPassword_RequireSchemaVersionMismatch(t *testing.T) {
	var stdout, stderr bytes.Buffer
	o := baseOptions(&stdout, &stderr)
	o.RequireSchemaVersion = 99
	err := runPassword(o)
	var ce *codedError
	if !errors.As(err, &ce) || ce.code != ExitInvalidArgs {
		t.Errorf("got %v, want ExitInvalidArgs", err)
	}
}

func TestRunPassword_RequireSchemaVersionMatch(t *testing.T) {
	var stdout, stderr bytes.Buffer
	o := baseOptions(&stdout, &stderr)
	o.RequireSchemaVersion = audit.SchemaVersion
	if err := runPassword(o); err != nil {
		t.Fatalf("runPassword: %v", err)
	}
}

func TestRunPassword_StdinParamsOverride(t *testing.T) {
	var stdout, stderr bytes.Buffer
	o := baseOptions(&stdout, &stderr)
	o.StdinParams = true
	o.stdin = strings.NewReader(`{"length": 32, "charset_id": "hex-v1"}`)
	o.JSON = true
	if err := runPassword(o); err != nil {
		t.Fatalf("runPassword: %v", err)
	}
	out := decodeJSON(t, stdout.Bytes())
	if out.Length != 32 {
		t.Errorf("length = %d, want 32 (from stdin)", out.Length)
	}
	if out.CharsetID != "hex-v1" {
		t.Errorf("charset_id = %q, want hex-v1 (from stdin)", out.CharsetID)
	}
}

func TestRunPassword_StdinParamsBadJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	o := baseOptions(&stdout, &stderr)
	o.StdinParams = true
	o.stdin = strings.NewReader(`not json`)
	err := runPassword(o)
	var ce *codedError
	if !errors.As(err, &ce) || ce.code != ExitInvalidArgs {
		t.Errorf("got %v, want ExitInvalidArgs", err)
	}
}

func TestRunPassword_StdinParamsUnknownField(t *testing.T) {
	var stdout, stderr bytes.Buffer
	o := baseOptions(&stdout, &stderr)
	o.StdinParams = true
	o.stdin = strings.NewReader(`{"unknown_field": 5}`)
	err := runPassword(o)
	var ce *codedError
	if !errors.As(err, &ce) || ce.code != ExitInvalidArgs {
		t.Errorf("got %v, want ExitInvalidArgs", err)
	}
}

func TestRunPassword_AuditLogAppendsAndRedacts(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")

	var stdout, stderr bytes.Buffer
	o := baseOptions(&stdout, &stderr)
	o.JSON = true
	o.AuditLogPath = logPath
	if err := runPassword(o); err != nil {
		t.Fatalf("runPassword: %v", err)
	}
	out := decodeJSON(t, stdout.Bytes())

	b, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), out.Password) {
		t.Errorf("audit log leaked password")
	}
	if !strings.Contains(string(b), audit.SHA256Hex(out.Password)) {
		t.Errorf("audit log missing password sha256")
	}
	if !strings.Contains(string(b), out.RequestID) {
		t.Errorf("audit log missing request_id")
	}
}

func TestRunPassword_AuditLogBadPath(t *testing.T) {
	var stdout, stderr bytes.Buffer
	o := baseOptions(&stdout, &stderr)
	o.AuditLogPath = filepath.Join(t.TempDir(), "no-such-dir", "audit.jsonl")
	err := runPassword(o)
	var ce *codedError
	if !errors.As(err, &ce) || ce.code != ExitInvalidArgs {
		t.Errorf("got %v, want ExitInvalidArgs", err)
	}
}

func TestCodedError_UnwrapAndError(t *testing.T) {
	inner := errors.New("boom")
	ce := &codedError{code: ExitRNGFailure, err: inner}
	if ce.Error() != "boom" {
		t.Errorf("Error() = %q", ce.Error())
	}
	if !errors.Is(ce, inner) {
		t.Errorf("errors.Is should match")
	}
	var nilCE *codedError
	if got := nilCE.Error(); got != "" {
		t.Errorf("nil codedError.Error() = %q", got)
	}
}

func TestFail_NilErrorReturnsNil(t *testing.T) {
	if got := fail(ExitInvalidArgs, nil); got != nil {
		t.Errorf("fail(_, nil) = %v, want nil", got)
	}
}

func TestRunPassword_StdinParamsAllFields(t *testing.T) {
	var stdout, stderr bytes.Buffer
	o := baseOptions(&stdout, &stderr)
	o.StdinParams = true
	o.JSON = true
	o.stdin = strings.NewReader(`{
		"length": 24,
		"charset_id": "alphanum-symbols-v1",
		"exclude": "0Ol1iI",
		"required_classes": "lower,upper,digit,symbol",
		"min_entropy_bits": 60,
		"allow_weak": true,
		"require_schema_version": 1
	}`)
	if err := runPassword(o); err != nil {
		t.Fatalf("runPassword: %v", err)
	}
	out := decodeJSON(t, stdout.Bytes())
	if out.Length != 24 {
		t.Errorf("length = %d, want 24", out.Length)
	}
	if out.CharsetID != "alphanum-symbols-v1+excluded" {
		t.Errorf("charset_id = %q", out.CharsetID)
	}
	if out.ExcludedCount != 6 {
		t.Errorf("excluded_count = %d, want 6", out.ExcludedCount)
	}
	if out.RequiredClasses != "lower,upper,digit,symbol" {
		t.Errorf("required_classes = %q", out.RequiredClasses)
	}
}

func TestRunPassword_UUIDFailureMapsToRNGFailure(t *testing.T) {
	var stdout, stderr bytes.Buffer
	o := baseOptions(&stdout, &stderr)
	o.uuid = func() (string, error) { return "", errors.New("uuid boom") }
	err := runPassword(o)
	var ce *codedError
	if !errors.As(err, &ce) || ce.code != ExitRNGFailure {
		t.Errorf("got %v, want ExitRNGFailure", err)
	}
}

type failingWriter struct{ err error }

func (f failingWriter) Write(_ []byte) (int, error) { return 0, f.err }

func TestRunPassword_JSONWriteFailure(t *testing.T) {
	var stderr bytes.Buffer
	o := baseOptions(failingWriter{err: errors.New("write boom")}, &stderr)
	o.JSON = true
	err := runPassword(o)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestRunPassword_PlaintextWriteFailureMapsToRNGFailure(t *testing.T) {
	var stderr bytes.Buffer
	o := baseOptions(failingWriter{err: errors.New("write boom")}, &stderr)
	err := runPassword(o)
	var ce *codedError
	if !errors.As(err, &ce) || ce.code != ExitRNGFailure {
		t.Errorf("got %v, want ExitRNGFailure", err)
	}
}

func TestNewRootCmd_FlagsRegistered(t *testing.T) {
	cmd := newRootCmd()
	if cmd.Use != "keygenerator" {
		t.Errorf("Use = %q", cmd.Use)
	}
	for _, name := range []string{
		"length", "charset", "exclude", "require-classes",
		"min-entropy-bits", "allow-weak", "json", "audit-log",
		"stdin-params", "require-schema-version",
	} {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("flag %q not registered", name)
		}
	}
	// The v1 flags must be gone.
	for _, removed := range []string{"letters", "special"} {
		if cmd.Flags().Lookup(removed) != nil {
			t.Errorf("flag %q should be removed in v2", removed)
		}
	}
}

func TestNewRootCmd_LongDescriptionNonEmpty(t *testing.T) {
	cmd := newRootCmd()
	if cmd.Long == "" {
		t.Error("Long should be non-empty")
	}
}
