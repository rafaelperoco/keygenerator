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
// hands it here for finalization. Errors emitted from inside emit() use
// the supplied errCtx so they get the same structured-JSON treatment as
// errors emitted from the validation path before emit() was called.
func emit(e errCtx, out audit.Output, password string) error {
	c := e.c
	if c.RequireSchemaVersion != 0 && c.RequireSchemaVersion != audit.SchemaVersion {
		return e.fail(ExitInvalidArgs, fmt.Errorf("require-schema-version=%d, but binary emits schema %d",
			c.RequireSchemaVersion, audit.SchemaVersion))
	}

	requestID, err := c.uuid()
	if err != nil {
		return e.fail(ExitRNGFailure, fmt.Errorf("request id: %w", err))
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
		if appendErr := audit.AppendLog(c.AuditLogPath, entry); appendErr != nil {
			return e.fail(ExitInvalidArgs, appendErr)
		}
	}

	if c.JSON {
		return writeJSON(c.stdout, out)
	}
	if _, err := fmt.Fprintln(c.stdout, password); err != nil {
		return e.fail(ExitRNGFailure, err)
	}
	if c.ShowCrackTime {
		printCrackTime(c.stdout, out.EntropyBits)
	}
	return nil
}

// errCtx is the context a subcommand needs to emit a structured JSON
// error envelope. Subcommands construct one near the top of their run
// function (where commonOpts and the subcommand name are both in scope)
// and call .fail(exitCode, err) instead of the global fail() in error
// paths. In --json mode this writes a schema-v1 envelope to stdout;
// otherwise it falls through to the legacy stderr behavior in main().
type errCtx struct {
	c          commonOpts
	subcommand string
}

func (e errCtx) fail(exitCode int, err error) error {
	if !e.c.JSON {
		return fail(exitCode, err)
	}
	if err == nil {
		return nil
	}

	requestID, idErr := e.c.uuid()
	if idErr != nil {
		// Fall back to a synthetic placeholder so the envelope is still
		// well-formed; the agent can correlate via timestamp.
		requestID = "00000000-0000-4000-8000-000000000000"
	}

	out := audit.Output{
		SchemaVersion: audit.SchemaVersion,
		Subcommand:    e.subcommand,
		Version:       version,
		Commit:        commit,
		BuildDate:     buildDate,
		RequestID:     requestID,
		TimestampUTC:  e.c.now().Format(time.RFC3339Nano),
		Error:         audit.NewError(exitToCode(exitCode), err.Error()),
	}
	if writeErr := writeJSON(e.c.stdout, out); writeErr != nil {
		// If we cannot even write to stdout, fall back to legacy stderr
		// so the agent at least gets *something*.
		return fail(exitCode, err)
	}
	return failJSON(exitCode, err)
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
