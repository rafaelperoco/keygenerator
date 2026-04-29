package main

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/rafaelperoco/keygenerator/internal/audit"
	"github.com/rafaelperoco/keygenerator/internal/charset"
	"github.com/rafaelperoco/keygenerator/internal/generator"
	"github.com/rafaelperoco/keygenerator/internal/policy"
	"github.com/spf13/cobra"
)

// MaxPINRejectionRetries caps how many candidate PINs we discard before
// giving up. With 4-digit PINs the blocklist+sequence rules reject ~5%
// of the 10000 space, so 100 retries gives a vanishingly small chance of
// false failure. For 6+ digit PINs the rejection rate is much lower.
const MaxPINRejectionRetries = 100

// pinOptions carries every flag for the `pin` subcommand. PINs are
// numeric-only by definition; their entropy is intrinsically low, so
// the floor defaults to 0 and an explicit --acknowledge-low-entropy
// flag is required to generate at all.
type pinOptions struct {
	commonOpts
	Digits                int
	AcknowledgeLowEntropy bool
	AllowWeakPattern      bool
}

type stdinPINRequest struct {
	Digits                *int  `json:"digits,omitempty"`
	AcknowledgeLowEntropy *bool `json:"acknowledge_low_entropy,omitempty"`
	AllowWeakPattern      *bool `json:"allow_weak_pattern,omitempty"`
	RequireSchemaVersion  *int  `json:"require_schema_version,omitempty"`
}

func newPINCmd() *cobra.Command {
	opts := &pinOptions{commonOpts: newCommonOpts()}
	cmd := &cobra.Command{
		Use:   "pin",
		Short: "Generate a numeric PIN with weak-pattern rejection",
		Long: `Generates a uniformly random numeric PIN of the given length, rejecting
candidates that match known weak patterns: all-same-digit, strict
sequences (1234, 9876), short repetitions (1212, 123123), the top-20
DataGenetics-2012 most-common PINs, and calendar years.

PINs are intrinsically low-entropy: a 4-digit PIN carries ~13.3 bits, a
6-digit PIN ~19.9 bits. This is far below any sensible password floor,
so generation requires an explicit --acknowledge-low-entropy flag. PINs
are appropriate only when the verifying system enforces strict rate
limits (banking, hardware tokens) — never as a primary authenticator.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPIN(*opts)
		},
	}

	cmd.Flags().IntVarP(&opts.Digits, "digits", "n", 6,
		"number of digits in the PIN")
	cmd.Flags().BoolVar(&opts.AcknowledgeLowEntropy, "acknowledge-low-entropy", false,
		"required acknowledgement that PINs are intrinsically low-entropy")
	cmd.Flags().BoolVar(&opts.AllowWeakPattern, "allow-weak-pattern", false,
		"permit PINs that match known weak patterns (NOT RECOMMENDED)")
	addCommonFlags(cmd, &opts.commonOpts)
	return cmd
}

func runPIN(o pinOptions) error {
	if o.StdinParams {
		req, err := readStdinPINParams(o.stdin)
		if err != nil {
			return fail(ExitInvalidArgs, err)
		}
		applyStdinPIN(&o, req)
	}
	if o.Digits < 4 {
		return fail(ExitInvalidArgs, fmt.Errorf("digits must be >= 4, got %d", o.Digits))
	}
	if !o.AcknowledgeLowEntropy {
		return fail(ExitEntropyTooLow,
			fmt.Errorf("PIN generation requires --acknowledge-low-entropy (PINs carry %0.1f bits, far below any password floor)",
				policy.EntropyBits(o.Digits, 10)))
	}

	cs, err := charset.Get("digit-v1")
	if err != nil {
		return fail(ExitRNGFailure, err)
	}

	var pin string
	for attempt := range MaxPINRejectionRetries {
		candidate, gerr := generator.Generate(generator.Request{
			Charset: cs,
			Length:  o.Digits,
		})
		if gerr != nil {
			return fail(ExitRNGFailure, gerr)
		}
		if o.AllowWeakPattern || !policy.IsWeakPIN(candidate) {
			pin = candidate
			break
		}
		if attempt == MaxPINRejectionRetries-1 {
			return fail(ExitRNGFailure,
				fmt.Errorf("could not produce a strong-pattern PIN after %d attempts", MaxPINRejectionRetries))
		}
	}

	bits := policy.EntropyBits(o.Digits, 10)
	out := audit.Output{
		Length:      o.Digits,
		CharsetID:   cs.ID,
		CharsetSize: cs.Size(),
		EntropyBits: bits,
		Algorithm:   "crypto/rand+weak-pin-rejection",
		Subcommand:  "pin",
		Warnings: []string{
			fmt.Sprintf("PIN entropy is %.1f bits; safe only with verifier-side rate limiting", bits),
		},
	}
	return emit(o.commonOpts, out, pin)
}

func readStdinPINParams(r io.Reader) (stdinPINRequest, error) {
	var req stdinPINRequest
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return req, fmt.Errorf("stdin-params: %w", err)
	}
	return req, nil
}

func applyStdinPIN(o *pinOptions, r stdinPINRequest) {
	if r.Digits != nil {
		o.Digits = *r.Digits
	}
	if r.AcknowledgeLowEntropy != nil {
		o.AcknowledgeLowEntropy = *r.AcknowledgeLowEntropy
	}
	if r.AllowWeakPattern != nil {
		o.AllowWeakPattern = *r.AllowWeakPattern
	}
	if r.RequireSchemaVersion != nil {
		o.RequireSchemaVersion = *r.RequireSchemaVersion
	}
}
