package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/rafaelperoco/keygenerator/internal/audit"
	"github.com/rafaelperoco/keygenerator/internal/charset"
	"github.com/rafaelperoco/keygenerator/internal/generator"
	"github.com/rafaelperoco/keygenerator/internal/policy"
	"github.com/spf13/cobra"
)

// runOptions consolidates every CLI flag and the supplied stdin params
// into a single struct so the runner is unit-testable independent of cobra.
type runOptions struct {
	Length                int
	CharsetID             string
	Exclude               string
	RequiredClassesSpec   string
	MinEntropyBits        float64
	AllowWeak             bool
	JSON                  bool
	AuditLogPath          string
	StdinParams           bool
	RequireSchemaVersion  int
	stdin                 io.Reader
	stdout                io.Writer
	stderr                io.Writer
	now                   func() time.Time
	uuid                  func() (string, error)
}

// stdinRequest mirrors the subset of runOptions exposed via --stdin-params
// JSON. Sensitive flags (audit-log path) are intentionally not accepted via
// stdin to keep filesystem effects driven by argv only.
type stdinRequest struct {
	Length              *int     `json:"length,omitempty"`
	CharsetID           *string  `json:"charset_id,omitempty"`
	Exclude             *string  `json:"exclude,omitempty"`
	RequiredClasses     *string  `json:"required_classes,omitempty"`
	MinEntropyBits      *float64 `json:"min_entropy_bits,omitempty"`
	AllowWeak           *bool    `json:"allow_weak,omitempty"`
	RequireSchemaVersion *int    `json:"require_schema_version,omitempty"`
}

func newRootCmd() *cobra.Command {
	opts := &runOptions{
		stdin:  os.Stdin,
		stdout: os.Stdout,
		stderr: os.Stderr,
		now:    func() time.Time { return time.Now().UTC() },
		uuid:   func() (string, error) { return audit.NewUUIDv4(nil) },
	}

	cmd := &cobra.Command{
		Use:           "keygenerator",
		Short:         "Generate auditable random passwords",
		Long:          longDescription(),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPassword(*opts)
		},
	}

	cmd.Flags().IntVarP(&opts.Length, "length", "n", 20, "length of the password")
	cmd.Flags().StringVarP(&opts.CharsetID, "charset", "c", "alphanum-v1",
		"named charset id ("+strings.Join(charset.IDs(), ", ")+")")
	cmd.Flags().StringVarP(&opts.Exclude, "exclude", "e", "", "characters to exclude from the charset")
	cmd.Flags().StringVar(&opts.RequiredClassesSpec, "require-classes", "",
		"comma-separated character classes required in the output (lower,upper,digit,symbol)")
	cmd.Flags().Float64Var(&opts.MinEntropyBits, "min-entropy-bits", 80,
		"minimum acceptable entropy in bits; 0 disables")
	cmd.Flags().BoolVar(&opts.AllowWeak, "allow-weak", false,
		"permit generation below the entropy floor (emits a warning)")
	cmd.Flags().BoolVar(&opts.JSON, "json", false, "emit a structured JSON record on stdout")
	cmd.Flags().StringVar(&opts.AuditLogPath, "audit-log", "",
		"append a redacted JSONL audit record to this file (mode 0600)")
	cmd.Flags().BoolVar(&opts.StdinParams, "stdin-params", false,
		"read a JSON request from stdin to populate flags (avoids argv leakage)")
	cmd.Flags().IntVar(&opts.RequireSchemaVersion, "require-schema-version", 0,
		"if set, fail unless the output schema version matches this value")

	return cmd
}

func longDescription() string {
	return `keygenerator produces random passwords with documented entropy and a
machine-readable audit trail. Suitable for invocation by AI agents and
automated systems that need verifiable provenance for generated secrets.`
}

func runPassword(o runOptions) error {
	if o.StdinParams {
		req, err := readStdinParams(o.stdin)
		if err != nil {
			return fail(ExitInvalidArgs, err)
		}
		applyStdin(&o, req)
	}

	if o.RequireSchemaVersion != 0 && o.RequireSchemaVersion != audit.SchemaVersion {
		return fail(ExitInvalidArgs, fmt.Errorf("require-schema-version=%d, but binary emits schema %d",
			o.RequireSchemaVersion, audit.SchemaVersion))
	}

	cs, err := charset.Get(o.CharsetID)
	if err != nil {
		return fail(ExitInvalidArgs, err)
	}

	excludedCount := 0
	excludedSHA := ""
	if o.Exclude != "" {
		excludedRunes := []rune(o.Exclude)
		excludedCount = len(excludedRunes)
		excludedSHA = audit.SHA256Hex(o.Exclude)
		cs, err = charset.Exclude(cs, excludedRunes)
		if err != nil {
			return fail(ExitCharsetEmpty, err)
		}
	}

	requiredClasses, err := policy.ParseClasses(o.RequiredClassesSpec)
	if err != nil {
		return fail(ExitInvalidArgs, err)
	}
	if err := policy.ValidateClassesAchievable(cs, o.Length, requiredClasses); err != nil {
		return fail(ExitClassImpossible, err)
	}

	bits := policy.EntropyBits(o.Length, cs.Size())
	var warnings []string
	if err := policy.EnforceFloor(bits, o.MinEntropyBits, o.AllowWeak); err != nil {
		return fail(ExitEntropyTooLow, err)
	}
	if o.MinEntropyBits > 0 && bits < o.MinEntropyBits && o.AllowWeak {
		warnings = append(warnings,
			fmt.Sprintf("entropy %.2f bits below floor %.2f (allow-weak set)", bits, o.MinEntropyBits))
	}

	pw, err := generator.Generate(generator.Request{
		Charset:         cs,
		Length:          o.Length,
		RequiredClasses: requiredClasses,
	})
	if err != nil {
		if errors.Is(err, generator.ErrClassExhausted) {
			return fail(ExitClassImpossible, err)
		}
		return fail(ExitRNGFailure, err)
	}

	requestID, err := o.uuid()
	if err != nil {
		return fail(ExitRNGFailure, fmt.Errorf("request id: %w", err))
	}

	out := audit.Output{
		SchemaVersion:   audit.SchemaVersion,
		Password:        pw,
		Length:          o.Length,
		CharsetID:       cs.ID,
		CharsetSize:     cs.Size(),
		EntropyBits:     bits,
		ExcludedCount:   excludedCount,
		ExcludedSHA256:  excludedSHA,
		RequiredClasses: policy.ClassesString(requiredClasses),
		Algorithm:       "crypto/rand+rejection-sampling",
		Subcommand:      "password",
		Version:         version,
		Commit:          commit,
		BuildDate:       buildDate,
		RequestID:       requestID,
		TimestampUTC:    o.now().Format(time.RFC3339Nano),
		Warnings:        warnings,
	}

	if o.AuditLogPath != "" {
		entry := audit.LogFromOutput(out, audit.SHA256Hex(pw))
		if err := audit.AppendLog(o.AuditLogPath, entry); err != nil {
			return fail(ExitInvalidArgs, err)
		}
	}

	if o.JSON {
		return writeJSON(o.stdout, out)
	}
	if _, err := fmt.Fprintln(o.stdout, pw); err != nil {
		return fail(ExitRNGFailure, err)
	}
	return nil
}

func writeJSON(w io.Writer, out audit.Output) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(out); err != nil {
		return fail(ExitInvalidArgs, err)
	}
	return nil
}

func readStdinParams(r io.Reader) (stdinRequest, error) {
	var req stdinRequest
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return req, fmt.Errorf("stdin-params: %w", err)
	}
	return req, nil
}

func applyStdin(o *runOptions, r stdinRequest) {
	if r.Length != nil {
		o.Length = *r.Length
	}
	if r.CharsetID != nil {
		o.CharsetID = *r.CharsetID
	}
	if r.Exclude != nil {
		o.Exclude = *r.Exclude
	}
	if r.RequiredClasses != nil {
		o.RequiredClassesSpec = *r.RequiredClasses
	}
	if r.MinEntropyBits != nil {
		o.MinEntropyBits = *r.MinEntropyBits
	}
	if r.AllowWeak != nil {
		o.AllowWeak = *r.AllowWeak
	}
	if r.RequireSchemaVersion != nil {
		o.RequireSchemaVersion = *r.RequireSchemaVersion
	}
}

