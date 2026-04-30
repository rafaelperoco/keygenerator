// Package audit defines the machine-readable output schema and the
// append-only audit log format. The schema version is part of the public
// contract: any breaking change to Output requires bumping SchemaVersion.
package audit

// SchemaVersion is the current output schema version. Increment on any
// breaking change to the Output struct (renamed/removed fields, changed
// semantics). Adding optional fields is non-breaking and does not require
// a bump.
const SchemaVersion = 1

// CrackTimeEstimate mirrors policy.CrackTimeEstimate but lives here so the
// audit package owns the on-the-wire shape. The duplication is intentional:
// it keeps internal/audit free of policy-package dependencies and makes the
// JSON contract self-contained.
type CrackTimeEstimate struct {
	ProfileID     string  `json:"profile_id"`
	Description   string  `json:"description"`
	Seconds       float64 `json:"seconds"`
	HumanReadable string  `json:"human_readable"`
}

// Output is the JSON document emitted on stdout when --json is set, and
// also the basis (with the password redacted) for an audit-log entry.
type Output struct {
	SchemaVersion      int                 `json:"schema_version"`
	Password           string              `json:"password,omitempty"`
	Length             int                 `json:"length"`
	CharsetID          string              `json:"charset_id"`
	CharsetSize        int                 `json:"charset_size"`
	EntropyBits        float64             `json:"entropy_bits"`
	ExcludedCount      int                 `json:"excluded_count"`
	ExcludedSHA256     string              `json:"excluded_sha256,omitempty"`
	RequiredClasses    string              `json:"required_classes,omitempty"`
	Algorithm          string              `json:"algorithm"`
	Subcommand         string              `json:"subcommand"`
	Version            string              `json:"version"`
	Commit             string              `json:"commit"`
	BuildDate          string              `json:"build_date"`
	RequestID          string              `json:"request_id"`
	TimestampUTC       string              `json:"timestamp_utc"`
	Warnings           []string            `json:"warnings,omitempty"`
	CrackTimeEstimates []CrackTimeEstimate `json:"crack_time_estimates,omitempty"`
}

// LogEntry is the redacted form written to the audit log file. It is
// derived from Output but never carries the password in plaintext: only
// its SHA-256 for post-hoc correlation.
type LogEntry struct {
	SchemaVersion      int                 `json:"schema_version"`
	PasswordSHA256     string              `json:"password_sha256"`
	Length             int                 `json:"length"`
	CharsetID          string              `json:"charset_id"`
	CharsetSize        int                 `json:"charset_size"`
	EntropyBits        float64             `json:"entropy_bits"`
	ExcludedCount      int                 `json:"excluded_count"`
	ExcludedSHA256     string              `json:"excluded_sha256,omitempty"`
	RequiredClasses    string              `json:"required_classes,omitempty"`
	Algorithm          string              `json:"algorithm"`
	Subcommand         string              `json:"subcommand"`
	Version            string              `json:"version"`
	Commit             string              `json:"commit"`
	BuildDate          string              `json:"build_date"`
	RequestID          string              `json:"request_id"`
	TimestampUTC       string              `json:"timestamp_utc"`
	Warnings           []string            `json:"warnings,omitempty"`
	CrackTimeEstimates []CrackTimeEstimate `json:"crack_time_estimates,omitempty"`
}

// LogFromOutput projects an Output into a LogEntry, replacing the
// plaintext password with passwordSHA256 (caller-supplied so this package
// has no opinion on hashing strategy beyond what callers do).
func LogFromOutput(o Output, passwordSHA256 string) LogEntry {
	return LogEntry{
		SchemaVersion:      o.SchemaVersion,
		PasswordSHA256:     passwordSHA256,
		Length:             o.Length,
		CharsetID:          o.CharsetID,
		CharsetSize:        o.CharsetSize,
		EntropyBits:        o.EntropyBits,
		ExcludedCount:      o.ExcludedCount,
		ExcludedSHA256:     o.ExcludedSHA256,
		RequiredClasses:    o.RequiredClasses,
		Algorithm:          o.Algorithm,
		Subcommand:         o.Subcommand,
		Version:            o.Version,
		Commit:             o.Commit,
		BuildDate:          o.BuildDate,
		RequestID:          o.RequestID,
		TimestampUTC:       o.TimestampUTC,
		Warnings:           o.Warnings,
		CrackTimeEstimates: o.CrackTimeEstimates,
	}
}
