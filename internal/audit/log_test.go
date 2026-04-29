package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSHA256Hex_KnownVector(t *testing.T) {
	got := SHA256Hex("abc")
	want := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got != want {
		t.Errorf("SHA256Hex(\"abc\") = %q, want %q", got, want)
	}
	// belt-and-braces: cross-check against the standard library directly.
	sum := sha256.Sum256([]byte("abc"))
	if hex.EncodeToString(sum[:]) != got {
		t.Errorf("inconsistent with stdlib")
	}
}

func TestAppendLog_CreatesFileMode0600(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file mode semantics differ on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	entry := LogEntry{
		SchemaVersion:  SchemaVersion,
		PasswordSHA256: SHA256Hex("hunter2"),
		Length:         20,
		CharsetID:      "alphanum-v1",
		CharsetSize:    62,
		EntropyBits:    119.08,
		Algorithm:      "crypto/rand",
		Subcommand:     "password",
		Version:        "v0.0.0",
		Commit:         "deadbeef",
		BuildDate:      "1970-01-01T00:00:00Z",
		RequestID:      "00000000-0000-0000-0000-000000000000",
		TimestampUTC:   "1970-01-01T00:00:00Z",
	}
	if err := AppendLog(path, entry); err != nil {
		t.Fatalf("AppendLog: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("file mode = %o, want 0600", got)
	}
}

func TestAppendLog_AppendsJSONL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	for i := range 3 {
		entry := LogEntry{
			SchemaVersion: SchemaVersion,
			RequestID:     "req-" + string(rune('a'+i)),
		}
		if err := AppendLog(path, entry); err != nil {
			t.Fatalf("AppendLog #%d: %v", i, err)
		}
	}

	f, err := os.Open(path) // #nosec G304 -- test temp file
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	scanner := bufio.NewScanner(f)
	count := 0
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "{") {
			t.Errorf("line %d not JSON: %q", count, line)
		}
		var got LogEntry
		if err := json.Unmarshal([]byte(line), &got); err != nil {
			t.Errorf("line %d not valid JSON: %v", count, err)
		}
		count++
	}
	if count != 3 {
		t.Errorf("got %d lines, want 3", count)
	}
}

func TestAppendLog_NoPasswordField(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	entry := LogEntry{
		SchemaVersion:  SchemaVersion,
		PasswordSHA256: SHA256Hex("topsecret"),
	}
	if err := AppendLog(path, entry); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path) // #nosec G304 -- test temp file
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "topsecret") {
		t.Errorf("audit log leaked plaintext password: %s", b)
	}
	if !strings.Contains(string(b), "password_sha256") {
		t.Errorf("audit log missing password_sha256 field: %s", b)
	}
	// Hard guarantee: no field literally named "password" present.
	if strings.Contains(string(b), `"password":`) {
		t.Errorf("audit log unexpectedly contains \"password\" field: %s", b)
	}
}

func TestAppendLog_OpenFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission semantics differ on Windows")
	}
	// A path under a non-existent directory cannot be opened with O_CREATE
	// because the parent does not exist.
	bad := filepath.Join(t.TempDir(), "no-such-dir", "audit.jsonl")
	if err := AppendLog(bad, LogEntry{SchemaVersion: SchemaVersion}); err == nil {
		t.Fatal("AppendLog with bad path returned nil error")
	}
}

func TestAppendLog_PreservesExistingContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(path, []byte(`{"schema_version":1,"request_id":"existing"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := AppendLog(path, LogEntry{SchemaVersion: SchemaVersion, RequestID: "added"}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path) // #nosec G304 -- test temp file
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"existing"`) || !strings.Contains(string(b), `"added"`) {
		t.Errorf("file did not preserve+append: %s", b)
	}
}

func TestLogFromOutput_RedactsPassword(t *testing.T) {
	o := Output{
		SchemaVersion: SchemaVersion,
		Password:      "topsecret",
		Length:        9,
		CharsetID:     "alphanum-v1",
	}
	le := LogFromOutput(o, SHA256Hex(o.Password))
	if le.PasswordSHA256 != SHA256Hex("topsecret") {
		t.Errorf("PasswordSHA256 mismatch: %s", le.PasswordSHA256)
	}
	// LogEntry has no Password field at all (compile-time guarantee), so
	// just verify projected fields:
	if le.Length != 9 || le.CharsetID != "alphanum-v1" {
		t.Errorf("projection mismatch: %+v", le)
	}
}
