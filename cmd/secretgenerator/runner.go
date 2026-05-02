package main

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/rafaelperoco/secretgenerator/internal/audit"
	"github.com/rafaelperoco/secretgenerator/internal/policy"
	"github.com/spf13/cobra"
)

// commonOpts is the subset of runOptions that every subcommand shares.
// Each subcommand has its own typed options struct that embeds commonOpts.
type commonOpts struct {
	JSON                 bool
	AuditLogPath         string
	StdinParams          bool
	RequireSchemaVersion int
	ShowCrackTime        bool
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
	cmd.Flags().BoolVar(&o.ShowCrackTime, "show-crack-time", false,
		"include crack-time estimates under named attacker profiles in the JSON output")
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
	if c.ShowCrackTime {
		out.CrackTimeEstimates = projectCrackTimes(out.EntropyBits)
	}

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
	if c.ShowCrackTime {
		printCrackTime(c.stdout, out.EntropyBits)
	}
	return nil
}

// projectCrackTimes converts policy.CrackTimeEstimate values into the
// audit.CrackTimeEstimate JSON shape. Kept private to the cmd package so
// the public Result type does not need to import audit transitively.
func projectCrackTimes(bits float64) []audit.CrackTimeEstimate {
	src := policy.EstimateCrackTimes(bits)
	out := make([]audit.CrackTimeEstimate, 0, len(src))
	for _, e := range src {
		out = append(out, audit.CrackTimeEstimate{
			ProfileID:     e.ProfileID,
			Description:   e.Description,
			Seconds:       e.Seconds,
			HumanReadable: e.HumanReadable,
		})
	}
	return out
}

// printCrackTime renders the crack-time estimates in plain mode after the
// generated credential. Emits to the same writer as the credential so a
// human running interactively gets immediate context; pipelines using
// --json get the structured form instead. Write errors are ignored
// (best-effort secondary output; the credential itself was already
// written successfully).
func printCrackTime(w io.Writer, bits float64) {
	_, _ = fmt.Fprintf(w, "\nentropy: %.2f bits\ntime to crack (average case):\n", bits)
	for _, e := range policy.EstimateCrackTimes(bits) {
		_, _ = fmt.Fprintf(w, "  %-30s %s\n", e.ProfileID, e.HumanReadable)
	}
}
