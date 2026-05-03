package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode"

	"github.com/rafaelperoco/secretgenerator/internal/audit"
	"github.com/rafaelperoco/secretgenerator/internal/charset"
	"github.com/rafaelperoco/secretgenerator/internal/policy"
	"github.com/spf13/cobra"
)

// entropyOptions carries every flag for the `entropy` subcommand. Unlike
// the other subcommands, this one CONSUMES a password (does not generate
// one) and reports its entropy assuming uniform random sampling from the
// observed character classes. --audit-log is intentionally NOT supported
// here: there is no produced credential to audit; the input password is
// the caller's existing material.
type entropyOptions struct {
	JSON                 bool
	StdinParams          bool
	RequireSchemaVersion int
	ShowCrackTime        bool
	Password             string
	FromArg              bool
	stdin                io.Reader
	stdout               io.Writer
	stderr               io.Writer
	now                  func() time.Time
	uuid                 func() (string, error)
}

type stdinEntropyRequest struct {
	Password             *string `json:"password,omitempty"`
	RequireSchemaVersion *int    `json:"require_schema_version,omitempty"`
}

func newEntropyCmd() *cobra.Command {
	c := newCommonOpts()
	opts := &entropyOptions{
		stdin:  c.stdin,
		stdout: c.stdout,
		stderr: c.stderr,
		now:    c.now,
		uuid:   c.uuid,
	}
	cmd := &cobra.Command{
		Use:   "entropy [password]",
		Short: "Estimate the entropy of a given password",
		Long: `Estimates the Shannon entropy of an existing password under the
assumption that each character was drawn uniformly from the observed
character class set. This is an UPPER BOUND; real entropy is lower if
the password follows a memorable pattern (dictionary word, year, name).

Read the password from:
  - the first positional argument (NOT recommended; visible in process listings)
  - stdin (preferred): secretgenerator entropy < password.txt
  - --stdin-params with JSON: {"password": "..."}

In plain mode the password is never echoed; only the entropy value is
printed. --json emits the full schema record but omits the plaintext
password (the caller already has it).`,
		Args:          cobra.MaximumNArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(_ *cobra.Command, args []string) error {
			if len(args) == 1 {
				opts.Password = args[0]
				opts.FromArg = true
			}
			return runEntropy(*opts)
		},
	}

	cmd.Flags().BoolVar(&opts.JSON, "json", false, "emit a structured JSON record on stdout")
	cmd.Flags().BoolVar(&opts.StdinParams, "stdin-params", false,
		"read a JSON request from stdin to populate flags (avoids argv leakage)")
	cmd.Flags().IntVar(&opts.RequireSchemaVersion, "require-schema-version", 0,
		"if set, fail unless the output schema version matches this value")
	cmd.Flags().BoolVar(&opts.ShowCrackTime, "show-crack-time", false,
		"include crack-time estimates under named attacker profiles")
	return cmd
}

func runEntropy(o entropyOptions) error {
	// Synthesize a minimal commonOpts-compatible context for error
	// reporting, since entropy has its own option struct rather than
	// embedding commonOpts.
	e := errCtx{
		c: commonOpts{
			JSON:   o.JSON,
			stdin:  o.stdin,
			stdout: o.stdout,
			stderr: o.stderr,
			now:    o.now,
			uuid:   o.uuid,
		},
		subcommand: "entropy",
	}

	if o.RequireSchemaVersion != 0 && o.RequireSchemaVersion != audit.SchemaVersion {
		return e.fail(ExitInvalidArgs, fmt.Errorf("require-schema-version=%d, but binary emits schema %d",
			o.RequireSchemaVersion, audit.SchemaVersion))
	}
	if o.StdinParams {
		req, err := readStdinEntropyParams(o.stdin)
		if err != nil {
			return e.fail(ExitInvalidArgs, err)
		}
		applyStdinEntropy(&o, req)
	} else if o.Password == "" {
		pw, err := readStdinPassword(o.stdin)
		if err != nil {
			return e.fail(ExitInvalidArgs, err)
		}
		o.Password = pw
	}
	if o.Password == "" {
		return e.fail(ExitInvalidArgs, fmt.Errorf("entropy: empty password"))
	}

	classes := observeClasses(o.Password)
	charsetSize := classSize(classes)
	bits := policy.EntropyBits(len(o.Password), charsetSize)

	var warnings []string
	if o.FromArg {
		warnings = append(warnings,
			"password supplied via argv (visible in process listings); prefer stdin for sensitive input")
	}

	if o.JSON {
		requestID, err := o.uuid()
		if err != nil {
			return e.fail(ExitRNGFailure, fmt.Errorf("request id: %w", err))
		}
		out := audit.Output{
			SchemaVersion:   audit.SchemaVersion,
			Length:          len(o.Password),
			CharsetID:       inferCharsetID(classes),
			CharsetSize:     charsetSize,
			EntropyBits:     bits,
			RequiredClasses: policy.ClassesString(classes),
			Algorithm:       "shannon-upper-bound",
			Subcommand:      "entropy",
			Version:         version,
			Commit:          commit,
			BuildDate:       buildDate,
			RequestID:       requestID,
			TimestampUTC:    o.now().Format(time.RFC3339Nano),
			Warnings:        warnings,
		}
		if o.ShowCrackTime {
			out.CrackTimeEstimates = projectCrackTimes(bits)
		}
		return writeJSON(o.stdout, out)
	}

	if _, err := fmt.Fprintf(o.stdout, "%.2f bits\n", bits); err != nil {
		return e.fail(ExitRNGFailure, err)
	}
	if o.ShowCrackTime {
		printCrackTime(o.stdout, bits)
	}
	return nil
}

func observeClasses(s string) charset.Class {
	var c charset.Class
	for _, r := range s {
		switch {
		case unicode.IsLower(r) && r <= 0x7F:
			c |= charset.ClassLower
		case unicode.IsUpper(r) && r <= 0x7F:
			c |= charset.ClassUpper
		case r >= '0' && r <= '9':
			c |= charset.ClassDigit
		default:
			c |= charset.ClassSymbol
		}
	}
	return c
}

func classSize(c charset.Class) int {
	size := 0
	if c&charset.ClassLower != 0 {
		size += 26
	}
	if c&charset.ClassUpper != 0 {
		size += 26
	}
	if c&charset.ClassDigit != 0 {
		size += 10
	}
	if c&charset.ClassSymbol != 0 {
		size += 32
	}
	return size
}

func inferCharsetID(c charset.Class) string {
	parts := []string{}
	if c&charset.ClassLower != 0 {
		parts = append(parts, "lower")
	}
	if c&charset.ClassUpper != 0 {
		parts = append(parts, "upper")
	}
	if c&charset.ClassDigit != 0 {
		parts = append(parts, "digit")
	}
	if c&charset.ClassSymbol != 0 {
		parts = append(parts, "symbol")
	}
	if len(parts) == 0 {
		return "empty"
	}
	return "observed:" + strings.Join(parts, "+")
}

func readStdinPassword(r io.Reader) (string, error) {
	br := bufio.NewReader(r)
	line, err := br.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	return strings.TrimRight(line, "\n"), nil
}

func readStdinEntropyParams(r io.Reader) (stdinEntropyRequest, error) {
	var req stdinEntropyRequest
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return req, fmt.Errorf("stdin-params: %w", err)
	}
	return req, nil
}

func applyStdinEntropy(o *entropyOptions, r stdinEntropyRequest) {
	if r.Password != nil {
		o.Password = *r.Password
	}
	if r.RequireSchemaVersion != nil {
		o.RequireSchemaVersion = *r.RequireSchemaVersion
	}
}
