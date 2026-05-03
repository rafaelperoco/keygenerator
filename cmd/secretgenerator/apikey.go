package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/rafaelperoco/secretgenerator/internal/audit"
	"github.com/rafaelperoco/secretgenerator/internal/charset"
	"github.com/rafaelperoco/secretgenerator/internal/generator"
	"github.com/rafaelperoco/secretgenerator/internal/policy"
	"github.com/spf13/cobra"
)

// apiKeyOptions carries every flag for the `api-key` subcommand. An API
// key is a string of the form `<prefix><separator><base62-secret>`, the
// pattern used by Stripe ("sk_live_..."), GitHub ("ghp_..."), Slack
// ("xoxb-..."), Anthropic ("sk-ant-..."), and most modern SaaS APIs.
type apiKeyOptions struct {
	commonOpts
	Prefix         string
	Separator      string
	Length         int
	MinEntropyBits float64
	AllowWeak      bool
}

type stdinAPIKeyRequest struct {
	Prefix               *string  `json:"prefix,omitempty"`
	Separator            *string  `json:"separator,omitempty"`
	Length               *int     `json:"length,omitempty"`
	MinEntropyBits       *float64 `json:"min_entropy_bits,omitempty"`
	AllowWeak            *bool    `json:"allow_weak,omitempty"`
	RequireSchemaVersion *int     `json:"require_schema_version,omitempty"`
}

func newAPIKeyCmd() *cobra.Command {
	opts := &apiKeyOptions{commonOpts: newCommonOpts()}
	cmd := &cobra.Command{
		Use:   "api-key",
		Short: "Generate an API-key-formatted token (prefix_base62)",
		Long: `Generates a token of the form <prefix><separator><base62> matching the
convention used by Stripe (sk_live_...), GitHub (ghp_...), Slack
(xoxb-...), Anthropic (sk-ant-...), and most modern SaaS APIs.

The base62 portion is drawn uniformly from a CSPRNG; entropy is reported
from the base62 length only — the prefix and separator are fixed and
contribute zero entropy to the credential.

Default length 32 base62 characters yields ~190 bits of entropy.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runAPIKey(*opts)
		},
	}

	cmd.Flags().StringVar(&opts.Prefix, "prefix", "sk",
		"static identifier prefix (e.g. \"sk\", \"ghp\", \"xoxb\")")
	cmd.Flags().StringVar(&opts.Separator, "separator", "_",
		"separator between prefix and secret body (e.g. \"_\", \"-\")")
	cmd.Flags().IntVarP(&opts.Length, "length", "n", 32,
		"length of the base62 secret body in characters")
	cmd.Flags().Float64Var(&opts.MinEntropyBits, "min-entropy-bits", 128,
		"minimum acceptable entropy in bits for the secret body; 0 disables")
	cmd.Flags().BoolVar(&opts.AllowWeak, "allow-weak", false,
		"permit generation below the entropy floor (emits a warning)")
	addCommonFlags(cmd, &opts.commonOpts)
	return cmd
}

func runAPIKey(o apiKeyOptions) error {
	e := errCtx{c: o.commonOpts, subcommand: "api-key"}
	if o.StdinParams {
		req, err := readStdinAPIKeyParams(o.stdin)
		if err != nil {
			return e.fail(ExitInvalidArgs, err)
		}
		applyStdinAPIKey(&o, req)
	}
	if o.Prefix == "" {
		return e.fail(ExitInvalidArgs, fmt.Errorf("prefix must not be empty"))
	}
	if strings.ContainsAny(o.Prefix, " \t\n\r") {
		return e.fail(ExitInvalidArgs, fmt.Errorf("prefix must not contain whitespace"))
	}
	if o.Length <= 0 {
		return e.fail(ExitInvalidArgs, fmt.Errorf("length must be > 0, got %d", o.Length))
	}

	cs, err := charset.Get("base62-v1")
	if err != nil {
		return e.fail(ExitRNGFailure, err)
	}

	bits := policy.EntropyBits(o.Length, cs.Size())
	var warnings []string
	if floorErr := policy.EnforceFloor(bits, o.MinEntropyBits, o.AllowWeak); floorErr != nil {
		return e.fail(ExitEntropyTooLow, floorErr)
	}
	if o.MinEntropyBits > 0 && bits < o.MinEntropyBits && o.AllowWeak {
		warnings = append(warnings,
			fmt.Sprintf("entropy %.2f bits below floor %.2f (allow-weak set)", bits, o.MinEntropyBits))
	}

	body, err := generator.Generate(generator.Request{
		Charset: cs,
		Length:  o.Length,
	})
	if err != nil {
		return e.fail(ExitRNGFailure, err)
	}
	token := o.Prefix + o.Separator + body

	out := audit.Output{
		Length:      o.Length,
		CharsetID:   cs.ID,
		CharsetSize: cs.Size(),
		EntropyBits: bits,
		Algorithm:   "crypto/rand+base62",
		Subcommand:  "api-key",
		Warnings:    warnings,
	}
	return emit(e, out, token)
}

func readStdinAPIKeyParams(r io.Reader) (stdinAPIKeyRequest, error) {
	var req stdinAPIKeyRequest
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return req, fmt.Errorf("stdin-params: %w", err)
	}
	return req, nil
}

func applyStdinAPIKey(o *apiKeyOptions, r stdinAPIKeyRequest) {
	if r.Prefix != nil {
		o.Prefix = *r.Prefix
	}
	if r.Separator != nil {
		o.Separator = *r.Separator
	}
	if r.Length != nil {
		o.Length = *r.Length
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
