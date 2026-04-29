package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

// AppendLog appends a single JSONL record to path. The file is created
// with mode 0600 if missing and is opened append-only. Writes are
// flushed before returning. Each record is exactly one line.
func AppendLog(path string, entry LogEntry) error {
	// #nosec G304 -- path is user-supplied via --audit-log; opening it
	// is the documented purpose of this function.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("audit: open %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	b, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("audit: marshal: %w", err)
	}
	b = append(b, '\n')
	if _, err := f.Write(b); err != nil {
		return fmt.Errorf("audit: write %q: %w", path, err)
	}
	return f.Sync()
}

// SHA256Hex returns the hex-encoded SHA-256 of s. Used for password and
// excluded-set fingerprints in audit records.
func SHA256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
