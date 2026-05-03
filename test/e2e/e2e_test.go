// Package e2e exercises the compiled secretgenerator binary end-to-end.
// It builds the binary into a tempdir, runs it with various flag
// combinations, and validates stdout/stderr/exit codes against the
// public CLI contract.
package e2e

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/rafaelperoco/secretgenerator/internal/audit"
)

// Documented exit codes (mirror cmd/secretgenerator/exit.go). exitRNGFailure
// (4) is intentionally not tested at the E2E layer because triggering a
// real entropy-source failure is impractical from outside the process;
// the unit test in internal/generator covers it directly.
const (
	exitOK              = 0
	exitInvalidArgs     = 2
	exitEntropyTooLow   = 3
	exitCharsetEmpty    = 5
	exitClassImpossible = 6
)

var (
	binaryPath string
	buildOnce  sync.Once
	buildErr   error
)

func keygenBinary(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "keygen-e2e-*")
		if err != nil {
			buildErr = err
			return
		}
		bin := filepath.Join(dir, "secretgenerator")
		if runtime.GOOS == "windows" {
			bin += ".exe"
		}
		// Walk up to find module root (go.mod).
		root, err := findModuleRoot()
		if err != nil {
			buildErr = err
			return
		}
		cmd := exec.Command("go", "build",
			"-ldflags=-X 'main.version=e2e' -X 'main.commit=test' -X 'main.buildDate=1970-01-01T00:00:00Z'",
			"-o", bin,
			"./cmd/secretgenerator")
		cmd.Dir = root
		out, err := cmd.CombinedOutput()
		if err != nil {
			buildErr = &buildFailure{out: out, err: err}
			return
		}
		binaryPath = bin
	})
	if buildErr != nil {
		t.Fatalf("build secretgenerator: %v", buildErr)
	}
	return binaryPath
}

type buildFailure struct {
	out []byte
	err error
}

func (b *buildFailure) Error() string {
	return b.err.Error() + ": " + string(b.out)
}

func findModuleRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	dir := wd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", os.ErrNotExist
		}
		dir = parent
	}
}

func runKeygen(t *testing.T, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	bin := keygenBinary(t)
	cmd := exec.Command(bin, args...)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	code = exitCodeFromError(t, err)
	return outBuf.String(), errBuf.String(), code
}

func runKeygenStdin(t *testing.T, stdinPayload string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	bin := keygenBinary(t)
	cmd := exec.Command(bin, args...)
	cmd.Stdin = strings.NewReader(stdinPayload)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	code = exitCodeFromError(t, err)
	return outBuf.String(), errBuf.String(), code
}

func exitCodeFromError(t *testing.T, err error) int {
	t.Helper()
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	t.Fatalf("exec: %v", err)
	return -1
}

// --- Tests ---

func TestE2E_BareInvocation(t *testing.T) {
	stdout, stderr, code := runKeygen(t)
	if code != exitOK {
		t.Errorf("exit=%d stderr=%q", code, stderr)
	}
	got := strings.TrimRight(stdout, "\n")
	if len(got) != 20 {
		t.Errorf("default length = %d, want 20", len(got))
	}
}

func TestE2E_PasswordJSONSchema(t *testing.T) {
	stdout, stderr, code := runKeygen(t, "--json")
	if code != exitOK {
		t.Fatalf("exit=%d stderr=%q", code, stderr)
	}
	out := decode(t, stdout)
	if out.SchemaVersion != audit.SchemaVersion {
		t.Errorf("schema_version = %d", out.SchemaVersion)
	}
	if out.Subcommand != "password" {
		t.Errorf("subcommand = %q", out.Subcommand)
	}
	if out.Version != "e2e" {
		t.Errorf("version = %q (ldflags not applied?)", out.Version)
	}
	mustValidUUID(t, out.RequestID)
}

func TestE2E_AllSubcommandsEmitValidSchema(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"password", []string{"password", "--json"}},
		{"secret", []string{"secret", "--json"}},
		{"api-key", []string{"api-key", "--json"}},
		{"pin", []string{"pin", "--json", "--acknowledge-low-entropy"}},
		{"passphrase", []string{"passphrase", "--json"}},
		{"entropy", []string{"entropy", "--json", "Tr0ub4dor&3"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stdout, stderr, code := runKeygen(t, tc.args...)
			if code != exitOK {
				t.Fatalf("exit=%d stderr=%q", code, stderr)
			}
			out := decode(t, stdout)
			if out.SchemaVersion != audit.SchemaVersion {
				t.Errorf("schema_version = %d", out.SchemaVersion)
			}
			if out.Subcommand != tc.name {
				t.Errorf("subcommand = %q, want %q", out.Subcommand, tc.name)
			}
			mustValidUUID(t, out.RequestID)
			if out.Algorithm == "" {
				t.Error("algorithm is empty")
			}
		})
	}
}

func TestE2E_ExitCode_InvalidArgs(t *testing.T) {
	_, _, code := runKeygen(t, "--charset", "no-such")
	if code != exitInvalidArgs {
		t.Errorf("exit=%d, want %d", code, exitInvalidArgs)
	}
}

func TestE2E_ExitCode_EntropyTooLow(t *testing.T) {
	_, _, code := runKeygen(t, "--length", "4")
	if code != exitEntropyTooLow {
		t.Errorf("exit=%d, want %d", code, exitEntropyTooLow)
	}
}

func TestE2E_ExitCode_CharsetEmpty(t *testing.T) {
	_, _, code := runKeygen(t, "--charset", "digit-v1", "--exclude", "0123456789", "--min-entropy-bits", "0")
	if code != exitCharsetEmpty {
		t.Errorf("exit=%d, want %d", code, exitCharsetEmpty)
	}
}

func TestE2E_ExitCode_ClassImpossible(t *testing.T) {
	_, _, code := runKeygen(t,
		"--charset", "digit-v1",
		"--require-classes", "symbol",
		"--min-entropy-bits", "0")
	if code != exitClassImpossible {
		t.Errorf("exit=%d, want %d", code, exitClassImpossible)
	}
}

func TestE2E_ExcludeBugFixed(t *testing.T) {
	// In v1, --exclude post-filtered: requesting 20 chars excluding all
	// lowercase produced fewer than 20 chars. v2 must produce exactly 20.
	stdout, stderr, code := runKeygen(t, "--length", "20", "--exclude", "abcdefghijklmnopqrstuvwxyz")
	if code != exitOK {
		t.Fatalf("exit=%d stderr=%q", code, stderr)
	}
	got := strings.TrimRight(stdout, "\n")
	if len(got) != 20 {
		t.Errorf("length = %d, want 20 (v1 bug must be fixed)", len(got))
	}
	for _, r := range got {
		if r >= 'a' && r <= 'z' {
			t.Errorf("excluded rune %q present in output %q", r, got)
		}
	}
}

func TestE2E_RequiredClassesGuarantee(t *testing.T) {
	for range 50 {
		stdout, stderr, code := runKeygen(t,
			"--charset", "alphanum-symbols-v1",
			"--length", "16",
			"--require-classes", "lower,upper,digit,symbol")
		if code != exitOK {
			t.Fatalf("exit=%d stderr=%q", code, stderr)
		}
		got := strings.TrimRight(stdout, "\n")
		hasL, hasU, hasD, hasS := false, false, false, false
		for _, r := range got {
			switch {
			case r >= 'a' && r <= 'z':
				hasL = true
			case r >= 'A' && r <= 'Z':
				hasU = true
			case r >= '0' && r <= '9':
				hasD = true
			default:
				hasS = true
			}
		}
		if !hasL || !hasU || !hasD || !hasS {
			t.Errorf("output %q missing required classes (l=%v u=%v d=%v s=%v)",
				got, hasL, hasU, hasD, hasS)
		}
	}
}

func TestE2E_StdinParams(t *testing.T) {
	payload := `{"length": 32, "charset_id": "hex-v1"}`
	stdout, stderr, code := runKeygenStdin(t, payload, "--stdin-params", "--json")
	if code != exitOK {
		t.Fatalf("exit=%d stderr=%q", code, stderr)
	}
	out := decode(t, stdout)
	if out.Length != 32 {
		t.Errorf("length = %d", out.Length)
	}
	if out.CharsetID != "hex-v1" {
		t.Errorf("charset_id = %q", out.CharsetID)
	}
}

func TestE2E_AuditLog(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	stdout, stderr, code := runKeygen(t, "--json", "--audit-log", logPath)
	if code != exitOK {
		t.Fatalf("exit=%d stderr=%q", code, stderr)
	}
	out := decode(t, stdout)
	b, err := os.ReadFile(logPath) // #nosec G304 -- test temp file
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), out.Password) {
		t.Errorf("audit log leaked password")
	}
	if !strings.Contains(string(b), out.RequestID) {
		t.Errorf("audit log missing request_id")
	}
	// Check file mode 0600 on POSIX. Windows does not honor POSIX mode
	// bits — file ACLs are different — so we skip this assertion there.
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(logPath)
		if mode := info.Mode().Perm(); mode != 0o600 {
			t.Errorf("audit log mode = %o, want 0600", mode)
		}
	}
}

func TestE2E_RequireSchemaVersionMismatch(t *testing.T) {
	_, _, code := runKeygen(t, "--require-schema-version", "99")
	if code != exitInvalidArgs {
		t.Errorf("exit=%d, want %d", code, exitInvalidArgs)
	}
}

func TestE2E_PasswordJSONOmitsExcludedSHA256WhenNotUsed(t *testing.T) {
	stdout, _, _ := runKeygen(t, "--json")
	if strings.Contains(stdout, `"excluded_sha256":""`) {
		t.Errorf("empty excluded_sha256 was emitted instead of being omitted: %s", stdout)
	}
}

func TestE2E_SecretEncodings(t *testing.T) {
	for _, enc := range []string{"base64url", "base64", "base32", "hex"} {
		t.Run(enc, func(t *testing.T) {
			stdout, _, code := runKeygen(t, "secret", "--encoding", enc, "--json")
			if code != exitOK {
				t.Fatalf("exit=%d", code)
			}
			out := decode(t, stdout)
			if !strings.Contains(out.CharsetID, enc) {
				t.Errorf("charset_id = %q does not mention encoding %q", out.CharsetID, enc)
			}
		})
	}
}

// TestE2E_StructuredErrorsInJSON verifies that every error path emits a
// schema-v1 JSON envelope with a populated Error field when --json is set,
// rather than plain prose on stderr. Agents branch on the stable string
// code (E_INVALID_ARGS, etc.) rather than the integer exit code.
func TestE2E_StructuredErrorsInJSON(t *testing.T) {
	cases := []struct {
		name     string
		args     []string
		exitCode int
		wantCode string
	}{
		{
			name:     "invalid charset",
			args:     []string{"--json", "--charset", "no-such"},
			exitCode: exitInvalidArgs,
			wantCode: "E_INVALID_ARGS",
		},
		{
			name:     "entropy too low",
			args:     []string{"--json", "--length", "4"},
			exitCode: exitEntropyTooLow,
			wantCode: "E_ENTROPY_TOO_LOW",
		},
		{
			name:     "charset empty after exclude",
			args:     []string{"--json", "--charset", "digit-v1", "--exclude", "0123456789", "--min-entropy-bits", "0"},
			exitCode: exitCharsetEmpty,
			wantCode: "E_CHARSET_EMPTY",
		},
		{
			name:     "class impossible",
			args:     []string{"--json", "--charset", "digit-v1", "--require-classes", "symbol", "--min-entropy-bits", "0"},
			exitCode: exitClassImpossible,
			wantCode: "E_CLASS_IMPOSSIBLE",
		},
		{
			name:     "schema version mismatch",
			args:     []string{"--json", "--require-schema-version", "99"},
			exitCode: exitInvalidArgs,
			wantCode: "E_INVALID_ARGS",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stdout, stderr, code := runKeygen(t, tc.args...)
			if code != tc.exitCode {
				t.Errorf("exit=%d, want %d (stderr=%q)", code, tc.exitCode, stderr)
			}
			if stdout == "" {
				t.Fatalf("expected JSON envelope on stdout, got empty (stderr=%q)", stderr)
			}
			out := decode(t, stdout)
			if out.SchemaVersion != audit.SchemaVersion {
				t.Errorf("schema_version = %d", out.SchemaVersion)
			}
			if out.Error == nil {
				t.Fatalf("error field missing from envelope; got %+v", out)
			}
			if out.Error.Code != tc.wantCode {
				t.Errorf("error.code = %q, want %q", out.Error.Code, tc.wantCode)
			}
			if out.Error.Message == "" {
				t.Errorf("error.message empty")
			}
			if out.Error.Hint == "" {
				t.Errorf("error.hint empty (expected curated remediation for known code)")
			}
			if out.Subcommand == "" {
				t.Errorf("subcommand should be populated even on failure")
			}
			if out.Version == "" {
				t.Errorf("version should be populated even on failure (build identity)")
			}
			mustValidUUID(t, out.RequestID)
			// Plain mode (no --json): same args without --json should print
			// to stderr instead — sanity check that we didn't break that path.
			plainArgs := []string{}
			for _, a := range tc.args {
				if a != "--json" {
					plainArgs = append(plainArgs, a)
				}
			}
			_, plainStderr, plainCode := runKeygen(t, plainArgs...)
			if plainCode != tc.exitCode {
				t.Errorf("plain mode exit=%d, want %d", plainCode, tc.exitCode)
			}
			if plainStderr == "" {
				t.Errorf("plain mode should still emit stderr on failure; got empty")
			}
		})
	}
}

// --- helpers ---

func decode(t *testing.T, s string) audit.Output {
	t.Helper()
	var out audit.Output
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		t.Fatalf("decode: %v\n%s", err, s)
	}
	return out
}

var uuidV4Re = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func mustValidUUID(t *testing.T, s string) {
	t.Helper()
	if !uuidV4Re.MatchString(s) {
		t.Errorf("UUID %q does not match v4", s)
	}
}
