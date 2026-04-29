package main

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/rafaelperoco/keygenerator/internal/audit"
	"github.com/spf13/cobra"
)

// commonOpts is the subset of runOptions that every subcommand shares.
// Each subcommand has its own typed options struct that embeds commonOpts.
type commonOpts struct {
	JSON                 bool
	AuditLogPath         string
	StdinParams          bool
	RequireSchemaVersion int
	stdin                io.Reader
	stdout               io.Writer
	stderr               io.Writer
	now                  func() time.Time
	uuid                 func() (string, error)
}

func newCommonOpts() commonOpts {
	return commonOpts{
		stdin:  os.Stdin,
		stdout: os.Stdout,
		stderr: os.Stderr,
		now:    func() time.Time { return time.Now().UTC() },
		uuid:   func() (string, error) { return audit.NewUUIDv4(nil) },
	}
}

// addCommonFlags wires the flags shared by every subcommand.
func addCommonFlags(cmd *cobra.Command, o *commonOpts) {
	cmd.Flags().BoolVar(&o.JSON, "json", false, "emit a structured JSON record on stdout")
	cmd.Flags().StringVar(&o.AuditLogPath, "audit-log", "",
		"append a redacted JSONL audit record to this file (mode 0600)")
	cmd.Flags().BoolVar(&o.StdinParams, "stdin-params", false,
		"read a JSON request from stdin to populate flags (avoids argv leakage)")
	cmd.Flags().IntVar(&o.RequireSchemaVersion, "require-schema-version", 0,
		"if set, fail unless the output schema version matches this value")
}

// emit stamps the audit envelope and writes the result. Each subcommand
// constructs an audit.Output with its own subcommand-specific fields and
// hands it here for finalization.
func emit(c commonOpts, out audit.Output, password string) error {
	if c.RequireSchemaVersion != 0 && c.RequireSchemaVersion != audit.SchemaVersion {
		return fail(ExitInvalidArgs, fmt.Errorf("require-schema-version=%d, but binary emits schema %d",
			c.RequireSchemaVersion, audit.SchemaVersion))
	}

	requestID, err := c.uuid()
	if err != nil {
		return fail(ExitRNGFailure, fmt.Errorf("request id: %w", err))
	}
	out.SchemaVersion = audit.SchemaVersion
	out.Password = password
	out.RequestID = requestID
	out.Version = version
	out.Commit = commit
	out.BuildDate = buildDate
	out.TimestampUTC = c.now().Format(time.RFC3339Nano)

	if c.AuditLogPath != "" {
		entry := audit.LogFromOutput(out, audit.SHA256Hex(password))
		if err := audit.AppendLog(c.AuditLogPath, entry); err != nil {
			return fail(ExitInvalidArgs, err)
		}
	}

	if c.JSON {
		return writeJSON(c.stdout, out)
	}
	if _, err := fmt.Fprintln(c.stdout, password); err != nil {
		return fail(ExitRNGFailure, err)
	}
	return nil
}
