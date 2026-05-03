package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rafaelperoco/secretgenerator/internal/audit"
)

// errCtxOpts builds a minimal errCtx with a deterministic uuid/now and a
// captured stdout buffer for assertions.
func errCtxOpts(t *testing.T, jsonMode bool) (errCtx, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	c := commonOpts{
		JSON:   jsonMode,
		stdout: &buf,
		now:    func() time.Time { return time.Date(2026, 5, 2, 22, 0, 0, 0, time.UTC) },
		uuid:   func() (string, error) { return "11111111-2222-4333-8444-555555555555", nil },
	}
	return errCtx{c: c, subcommand: "password"}, &buf
}

func TestErrCtx_PlainModeFallsThrough(t *testing.T) {
	e, buf := errCtxOpts(t, false)
	err := e.fail(ExitInvalidArgs, errors.New("synthetic"))
	if err == nil {
		t.Fatal("expected error")
	}
	if buf.Len() != 0 {
		t.Errorf("plain mode should not write to stdout, got %q", buf.String())
	}
	var ce *codedError
	if !errors.As(err, &ce) {
		t.Fatalf("expected *codedError, got %T", err)
	}
	if ce.code != ExitInvalidArgs {
		t.Errorf("code = %d", ce.code)
	}
	if ce.jsonEmitted {
		t.Errorf("plain mode must not set jsonEmitted")
	}
}

func TestErrCtx_JSONModeEmitsEnvelope(t *testing.T) {
	e, buf := errCtxOpts(t, true)
	err := e.fail(ExitEntropyTooLow, errors.New("policy: entropy below floor"))
	if err == nil {
		t.Fatal("expected error")
	}
	var ce *codedError
	if !errors.As(err, &ce) {
		t.Fatalf("expected *codedError, got %T", err)
	}
	if !ce.jsonEmitted {
		t.Errorf("JSON mode must set jsonEmitted")
	}
	if ce.code != ExitEntropyTooLow {
		t.Errorf("code = %d, want %d", ce.code, ExitEntropyTooLow)
	}

	var out audit.Output
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v\n%s", err, buf.String())
	}
	if out.SchemaVersion != audit.SchemaVersion {
		t.Errorf("schema_version = %d", out.SchemaVersion)
	}
	if out.Error == nil {
		t.Fatalf("error field missing")
	}
	if out.Error.Code != audit.CodeEntropyTooLow {
		t.Errorf("error.code = %q, want %q", out.Error.Code, audit.CodeEntropyTooLow)
	}
	if out.Error.Hint == "" {
		t.Errorf("error.hint should be populated for known code")
	}
	if out.Subcommand != "password" {
		t.Errorf("subcommand = %q", out.Subcommand)
	}
	if out.RequestID == "" {
		t.Errorf("request_id missing")
	}
	if out.TimestampUTC == "" {
		t.Errorf("timestamp_utc missing")
	}
	if out.Password != "" {
		t.Errorf("password should not be present on failure path")
	}
}

func TestErrCtx_NilError(t *testing.T) {
	e, _ := errCtxOpts(t, true)
	if got := e.fail(ExitInvalidArgs, nil); got != nil {
		t.Errorf("nil error should yield nil, got %v", got)
	}
}

func TestErrCtx_UUIDFailureUsesPlaceholder(t *testing.T) {
	var buf bytes.Buffer
	c := commonOpts{
		JSON:   true,
		stdout: &buf,
		now:    func() time.Time { return time.Date(2026, 5, 2, 22, 0, 0, 0, time.UTC) },
		uuid:   func() (string, error) { return "", errors.New("synthetic uuid failure") },
	}
	e := errCtx{c: c, subcommand: "secret"}
	err := e.fail(ExitRNGFailure, errors.New("rng down"))
	if err == nil {
		t.Fatal("expected error")
	}
	var out audit.Output
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.RequestID != "00000000-0000-4000-8000-000000000000" {
		t.Errorf("request_id placeholder = %q", out.RequestID)
	}
	if out.Subcommand != "secret" {
		t.Errorf("subcommand = %q", out.Subcommand)
	}
}

type failingWriter2 struct{ err error }

func (f failingWriter2) Write(_ []byte) (int, error) { return 0, f.err }

func TestErrCtx_StdoutWriteFailureFallsBackToLegacy(t *testing.T) {
	c := commonOpts{
		JSON:   true,
		stdout: failingWriter2{err: errors.New("write closed")},
		now:    func() time.Time { return time.Now().UTC() },
		uuid:   func() (string, error) { return "11111111-2222-4333-8444-555555555555", nil },
	}
	e := errCtx{c: c, subcommand: "password"}
	err := e.fail(ExitCharsetEmpty, errors.New("empty"))
	if err == nil {
		t.Fatal("expected error")
	}
	var ce *codedError
	if !errors.As(err, &ce) {
		t.Fatalf("expected codedError")
	}
	if ce.jsonEmitted {
		t.Errorf("must not claim JSON emitted when stdout write failed")
	}
	if ce.code != ExitCharsetEmpty {
		t.Errorf("code = %d", ce.code)
	}
}

func TestExitToCode_AllKnownCodes(t *testing.T) {
	tests := map[int]string{
		ExitInvalidArgs:     audit.CodeInvalidArgs,
		ExitEntropyTooLow:   audit.CodeEntropyTooLow,
		ExitRNGFailure:      audit.CodeRNGFailure,
		ExitCharsetEmpty:    audit.CodeCharsetEmpty,
		ExitClassImpossible: audit.CodeClassImpossible,
		// Unknown integer falls back to E_INVALID_ARGS as a safe default.
		999: audit.CodeInvalidArgs,
	}
	for input, want := range tests {
		if got := exitToCode(input); got != want {
			t.Errorf("exitToCode(%d) = %q, want %q", input, got, want)
		}
	}
}

func TestFailJSON_NilError(t *testing.T) {
	if got := failJSON(ExitInvalidArgs, nil); got != nil {
		t.Errorf("failJSON(_, nil) = %v, want nil", got)
	}
}

func TestFailJSON_SetsJSONEmittedFlag(t *testing.T) {
	err := failJSON(ExitRNGFailure, errors.New("boom"))
	var ce *codedError
	if !errors.As(err, &ce) {
		t.Fatalf("expected codedError")
	}
	if !ce.jsonEmitted {
		t.Errorf("failJSON must set jsonEmitted=true")
	}
	if ce.code != ExitRNGFailure {
		t.Errorf("code = %d", ce.code)
	}
	if !strings.Contains(ce.Error(), "boom") {
		t.Errorf("error wraps message: %v", ce.Error())
	}
}
