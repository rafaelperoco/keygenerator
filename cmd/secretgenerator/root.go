package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/rafaelperoco/secretgenerator/internal/audit"
	"github.com/rafaelperoco/secretgenerator/internal/charset"
	"github.com/rafaelperoco/secretgenerator/internal/generator"
	"github.com/rafaelperoco/secretgenerator/internal/policy"
	"github.com/spf13/cobra"
)

// runOptions carries every flag for the default `password` subcommand.
type runOptions struct {
	commonOpts
	Length              int
	CharsetID           string
	Exclude             string
	RequiredClassesSpec string
	MinEntropyBits      float64
	AllowWeak           bool
}

type stdinPasswordRequest struct {
	Length               *int     `json:"length,omitempty"`
	CharsetID            *string  `json:"charset_id,omitempty"`
	Exclude              *string  `json:"exclude,omitempty"`
	RequiredClasses      *string  `json:"required_classes,omitempty"`
	MinEntropyBits       *float64 `json:"min_entropy_bits,omitempty"`
	AllowWeak            *bool    `json:"allow_weak,omitempty"`
	RequireSchemaVersion *int     `json:"require_schema_version,omitempty"`
}

// newRootCmd builds the cobra command tree. The root command, when invoked
// without a subcommand, behaves identically to `secretgenerator password` —
// it shares the same flag set and runner as the password subcommand.
func newRootCmd() *cobra.Command {
	opts := &runOptions{commonOpts: newCommonOpts()}

	root := &cobra.Command{
		Use:           "secretgenerator",
		Short:         "Generate auditable random passwords",
		Long:          longDescription(),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runPassword(*opts)
		},
	}
	addPasswordFlags(root, opts)

	root.AddCommand(newPasswordCmd())
	root.AddCommand(newSecretCmd())
	root.AddCommand(newAPIKeyCmd())
	root.AddCommand(newPINCmd())
	root.AddCommand(newEntropyCmd())
	root.AddCommand(newPassphraseCmd())

	return root
}

func newPasswordCmd() *cobra.Command {
	opts := &runOptions{commonOpts: newCommonOpts()}
	cmd := &cobra.Command{
		Use:           "password",
		Short:         "Generate a random password from a named charset",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runPassword(*opts)
		},
	}
	addPasswordFlags(cmd, opts)
	return cmd
}

func addPasswordFlags(cmd *cobra.Command, opts *runOptions) {
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
	addCommonFlags(cmd, &opts.commonOpts)
}

func longDescription() string {
	return `secretgenerator produces random passwords with documented entropy and a
machine-readable audit trail. Suitable for invocation by AI agents and
automated systems that need verifiable provenance for generated secrets.`
}

func runPassword(o runOptions) error {
	if o.StdinParams {
		req, err := readStdinPasswordParams(o.stdin)
		if err != nil {
			return fail(ExitInvalidArgs, err)
		}
		applyStdinPassword(&o, req)
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
	if validateErr := policy.ValidateClassesAchievable(cs, o.Length, requiredClasses); validateErr != nil {
		return fail(ExitClassImpossible, validateErr)
	}

	bits := policy.EntropyBits(o.Length, cs.Size())
	var warnings []string
	if floorErr := policy.EnforceFloor(bits, o.MinEntropyBits, o.AllowWeak); floorErr != nil {
		return fail(ExitEntropyTooLow, floorErr)
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

	out := audit.Output{
		Length:          o.Length,
		CharsetID:       cs.ID,
		CharsetSize:     cs.Size(),
		EntropyBits:     bits,
		ExcludedCount:   excludedCount,
		ExcludedSHA256:  excludedSHA,
		RequiredClasses: policy.ClassesString(requiredClasses),
		Algorithm:       "crypto/rand+rejection-sampling",
		Subcommand:      "password",
		Warnings:        warnings,
	}

	return emit(o.commonOpts, out, pw)
}

func writeJSON(w io.Writer, out audit.Output) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(out); err != nil {
		return fail(ExitInvalidArgs, err)
	}
	return nil
}

func readStdinPasswordParams(r io.Reader) (stdinPasswordRequest, error) {
	var req stdinPasswordRequest
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return req, fmt.Errorf("stdin-params: %w", err)
	}
	return req, nil
}

func applyStdinPassword(o *runOptions, r stdinPasswordRequest) {
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
