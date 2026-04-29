package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"strings"

	"github.com/rafaelperoco/keygenerator/internal/audit"
	"github.com/rafaelperoco/keygenerator/internal/policy"
	"github.com/rafaelperoco/keygenerator/internal/words"
	"github.com/spf13/cobra"
)

// passphraseOptions carries every flag for the `passphrase` subcommand.
//
// Defaults are calibrated for AI-agent use cases where there is no human
// memorization burden:
//   - 8 words (~103 bits): clears Reinhold's "secure through 2050" line
//     and exceeds NIST SP 800-63B-4 implicit floors with margin.
//   - hyphen separator: shell/URL/env-file safe, preserves word boundaries.
//   - lowercase: predictable Title-Case is in every Hashcat ruleset
//     (Schneier 2014); --capitalize is exposed only as a compatibility
//     flag for systems that mandate uppercase, and emits a warning.
//   - no digit suffix: appended digits are the most-attacked transformation
//     (~25% of cracked passwords per Schneier 2014); --digit-suffix is a
//     compatibility flag with a warning.
type passphraseOptions struct {
	commonOpts
	Words          int
	Separator      string
	Capitalize     bool
	DigitSuffix    bool
	MinEntropyBits float64
	AllowWeak      bool
}

type stdinPassphraseRequest struct {
	Words                *int     `json:"words,omitempty"`
	Separator            *string  `json:"separator,omitempty"`
	Capitalize           *bool    `json:"capitalize,omitempty"`
	DigitSuffix          *bool    `json:"digit_suffix,omitempty"`
	MinEntropyBits       *float64 `json:"min_entropy_bits,omitempty"`
	AllowWeak            *bool    `json:"allow_weak,omitempty"`
	RequireSchemaVersion *int     `json:"require_schema_version,omitempty"`
}

func newPassphraseCmd() *cobra.Command {
	opts := &passphraseOptions{commonOpts: newCommonOpts()}
	cmd := &cobra.Command{
		Use:   "passphrase",
		Short: "Generate a diceware passphrase from the EFF Large Wordlist",
		Long: `Generates a passphrase by drawing words uniformly from the EFF Large
Wordlist (7776 words, ~12.92 bits/word) using a CSPRNG.

Default 8 words yields ~103 bits of entropy, which exceeds the
"secure-through-2050" threshold per Reinhold (Diceware author) and
clears any sensible password policy with comfortable margin. This
default targets AI-agent and machine-readable scenarios where there is
no human memorization burden; if you intend to memorize, 6 words
(~77 bits) is the EFF-published minimum.

The default separator is a hyphen — it preserves word boundaries
(without a separator, "in put" can be rebuilt as "input" and lose
entropy at the seam) and works in shells, URLs, env files, and JSON.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPassphrase(*opts)
		},
	}

	cmd.Flags().IntVarP(&opts.Words, "words", "w", 8,
		"number of words drawn from the EFF Large Wordlist")
	cmd.Flags().StringVar(&opts.Separator, "separator", "-",
		"string placed between consecutive words (e.g. \"-\", \" \", \".\")")
	cmd.Flags().BoolVar(&opts.Capitalize, "capitalize", false,
		"capitalize the first letter of each word (compatibility flag; does not strengthen)")
	cmd.Flags().BoolVar(&opts.DigitSuffix, "digit-suffix", false,
		"append a single random digit (compatibility flag; ~3.3 bits, prefer adding a word instead)")
	cmd.Flags().Float64Var(&opts.MinEntropyBits, "min-entropy-bits", 80,
		"minimum acceptable entropy in bits; 0 disables. Default 80 follows EFF/Reinhold floor")
	cmd.Flags().BoolVar(&opts.AllowWeak, "allow-weak", false,
		"permit generation below the entropy floor (emits a warning)")
	addCommonFlags(cmd, &opts.commonOpts)
	return cmd
}

func runPassphrase(o passphraseOptions) error {
	if o.StdinParams {
		req, err := readStdinPassphraseParams(o.stdin)
		if err != nil {
			return fail(ExitInvalidArgs, err)
		}
		applyStdinPassphrase(&o, req)
	}
	if o.Words <= 0 {
		return fail(ExitInvalidArgs, fmt.Errorf("words must be > 0, got %d", o.Words))
	}
	if o.Separator == "" {
		return fail(ExitInvalidArgs,
			fmt.Errorf("separator must not be empty (without a separator, adjacent words can fuse, leaking entropy at boundaries)"))
	}

	wordsBits := float64(o.Words) * words.EFFLargeBitsPerWord
	digitBits := 0.0
	if o.DigitSuffix {
		digitBits = 3.321928094887362 // log2(10)
	}
	bits := wordsBits + digitBits

	var warnings []string
	if err := policy.EnforceFloor(bits, o.MinEntropyBits, o.AllowWeak); err != nil {
		return fail(ExitEntropyTooLow, err)
	}
	if o.MinEntropyBits > 0 && bits < o.MinEntropyBits && o.AllowWeak {
		warnings = append(warnings,
			fmt.Sprintf("entropy %.2f bits below floor %.2f (allow-weak set)", bits, o.MinEntropyBits))
	}
	if o.Capitalize {
		warnings = append(warnings,
			"--capitalize is a compatibility flag; predictable Title-Case is in every Hashcat ruleset and adds ~0 bits against real attackers (prefer adding a word)")
	}
	if o.DigitSuffix {
		warnings = append(warnings,
			"--digit-suffix is a compatibility flag; appended digits are the #1 attacked transformation. Prefer adding a word (+12.92 bits) over a digit (+3.32 bits)")
	}

	picked, err := words.PickEFFLarge(o.Words, nil)
	if err != nil {
		return fail(ExitRNGFailure, err)
	}
	if o.Capitalize {
		for i, w := range picked {
			picked[i] = capitalizeFirst(w)
		}
	}
	phrase := strings.Join(picked, o.Separator)
	if o.DigitSuffix {
		d, err := pickDigit()
		if err != nil {
			return fail(ExitRNGFailure, err)
		}
		phrase = phrase + d
	}

	out := audit.Output{
		Length:      o.Words,
		CharsetID:   "eff-large-v1",
		CharsetSize: words.EFFLargeWordCount,
		EntropyBits: bits,
		Algorithm:   "diceware/eff-large-v1",
		Subcommand:  "passphrase",
		Warnings:    warnings,
	}
	return emit(o.commonOpts, out, phrase)
}

func capitalizeFirst(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	if r[0] >= 'a' && r[0] <= 'z' {
		r[0] = r[0] - 'a' + 'A'
	}
	return string(r)
}

// pickDigit returns a single uniformly-random decimal digit using
// crypto/rand.Int (which itself uses rejection sampling internally to
// avoid modulo bias).
func pickDigit() (string, error) {
	idx, err := rand.Int(rand.Reader, big.NewInt(10))
	if err != nil {
		return "", fmt.Errorf("digit-suffix: %w", err)
	}
	return fmt.Sprintf("%d", idx.Int64()), nil
}

func readStdinPassphraseParams(r io.Reader) (stdinPassphraseRequest, error) {
	var req stdinPassphraseRequest
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return req, fmt.Errorf("stdin-params: %w", err)
	}
	return req, nil
}

func applyStdinPassphrase(o *passphraseOptions, r stdinPassphraseRequest) {
	if r.Words != nil {
		o.Words = *r.Words
	}
	if r.Separator != nil {
		o.Separator = *r.Separator
	}
	if r.Capitalize != nil {
		o.Capitalize = *r.Capitalize
	}
	if r.DigitSuffix != nil {
		o.DigitSuffix = *r.DigitSuffix
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
