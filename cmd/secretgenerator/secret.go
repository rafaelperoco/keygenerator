package main

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"

	"github.com/rafaelperoco/secretgenerator/internal/audit"
	"github.com/rafaelperoco/secretgenerator/internal/policy"
	"github.com/spf13/cobra"
)

// secretOptions carries every flag for the `secret` subcommand. Unlike
// `password`, secret does not draw from a printable charset — it draws
// raw bytes from the entropy source and encodes them. It is the
// recommended subcommand for machine-to-machine secrets.
type secretOptions struct {
	commonOpts
	Bytes          int
	Encoding       string
	Prefix         string
	MinEntropyBits float64
	AllowWeak      bool
}

type stdinSecretRequest struct {
	Bytes                *int     `json:"bytes,omitempty"`
	Encoding             *string  `json:"encoding,omitempty"`
	Prefix               *string  `json:"prefix,omitempty"`
	MinEntropyBits       *float64 `json:"min_entropy_bits,omitempty"`
	AllowWeak            *bool    `json:"allow_weak,omitempty"`
	RequireSchemaVersion *int     `json:"require_schema_version,omitempty"`
}

func newSecretCmd() *cobra.Command {
	opts := &secretOptions{commonOpts: newCommonOpts()}
	cmd := &cobra.Command{
		Use:   "secret",
		Short: "Generate a high-entropy machine-readable secret (recommended for AI agents)",
		Long: `Generates raw random bytes from the OS CSPRNG and encodes them. Unlike
'password', this subcommand does not optimize for human readability or
keyboard typing; it is the recommended primitive for machine-to-machine
credentials, API tokens, and seed material.

Default is 32 bytes (256 bits of entropy) encoded as URL-safe base64
without padding, which yields a 43-character token suitable for use in
URLs, HTTP headers, environment variables, and JSON payloads.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runSecret(*opts)
		},
	}

	cmd.Flags().IntVarP(&opts.Bytes, "bytes", "b", 32,
		"number of random bytes to generate (8 bits each)")
	cmd.Flags().StringVarP(&opts.Encoding, "encoding", "E", "base64url",
		"output encoding: base64url, base64, base32, hex")
	cmd.Flags().StringVar(&opts.Prefix, "prefix", "",
		"static prefix prepended to the encoded secret (e.g. \"sk_\"); not counted toward entropy")
	cmd.Flags().Float64Var(&opts.MinEntropyBits, "min-entropy-bits", 128,
		"minimum acceptable entropy in bits; 0 disables. Default 128 follows NIST SP 800-131A target")
	cmd.Flags().BoolVar(&opts.AllowWeak, "allow-weak", false,
		"permit generation below the entropy floor (emits a warning)")
	addCommonFlags(cmd, &opts.commonOpts)
	return cmd
}

func runSecret(o secretOptions) error {
	e := errCtx{c: o.commonOpts, subcommand: "secret"}
	if o.StdinParams {
		req, err := readStdinSecretParams(o.stdin)
		if err != nil {
			return e.fail(ExitInvalidArgs, err)
		}
		applyStdinSecret(&o, req)
	}

	if o.Bytes <= 0 {
		return e.fail(ExitInvalidArgs, fmt.Errorf("bytes must be > 0, got %d", o.Bytes))
	}
	if !validEncoding(o.Encoding) {
		return e.fail(ExitInvalidArgs, fmt.Errorf("unknown encoding %q (want base64url, base64, base32, hex)", o.Encoding))
	}

	bits := float64(o.Bytes) * 8
	var warnings []string
	if err := policy.EnforceFloor(bits, o.MinEntropyBits, o.AllowWeak); err != nil {
		return e.fail(ExitEntropyTooLow, err)
	}
	if o.MinEntropyBits > 0 && bits < o.MinEntropyBits && o.AllowWeak {
		warnings = append(warnings,
			fmt.Sprintf("entropy %.2f bits below floor %.2f (allow-weak set)", bits, o.MinEntropyBits))
	}

	raw := make([]byte, o.Bytes)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return e.fail(ExitRNGFailure, fmt.Errorf("entropy source: %w", err))
	}
	encoded := encode(raw, o.Encoding)
	zeroize(raw)
	secret := o.Prefix + encoded

	out := audit.Output{
		Length:      len(secret),
		CharsetID:   "secret-bytes:" + o.Encoding,
		CharsetSize: 256,
		EntropyBits: bits,
		Algorithm:   "crypto/rand:bytes+" + o.Encoding,
		Subcommand:  "secret",
		Warnings:    warnings,
	}
	return emit(e, out, secret)
}

func validEncoding(e string) bool {
	switch e {
	case "base64url", "base64", "base32", "hex":
		return true
	}
	return false
}

func encode(raw []byte, e string) string {
	switch e {
	case "base64url":
		return base64.RawURLEncoding.EncodeToString(raw)
	case "base64":
		return base64.StdEncoding.EncodeToString(raw)
	case "base32":
		return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	case "hex":
		return hex.EncodeToString(raw)
	}
	// Unreachable: validEncoding gates this.
	panic("unreachable: invalid encoding " + e)
}

// zeroize overwrites b with zeros. Best-effort: Go's runtime may have made
// copies during use that we cannot reach. Documented in docs/CRYPTO.md.
func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func readStdinSecretParams(r io.Reader) (stdinSecretRequest, error) {
	var req stdinSecretRequest
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return req, fmt.Errorf("stdin-params: %w", err)
	}
	return req, nil
}

func applyStdinSecret(o *secretOptions, r stdinSecretRequest) {
	if r.Bytes != nil {
		o.Bytes = *r.Bytes
	}
	if r.Encoding != nil {
		o.Encoding = *r.Encoding
	}
	if r.Prefix != nil {
		o.Prefix = *r.Prefix
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
