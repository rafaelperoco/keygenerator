package secretgen

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"time"

	"github.com/rafaelperoco/secretgenerator/internal/audit"
	"github.com/rafaelperoco/secretgenerator/internal/charset"
	"github.com/rafaelperoco/secretgenerator/internal/generator"
	"github.com/rafaelperoco/secretgenerator/internal/policy"
	"github.com/rafaelperoco/secretgenerator/internal/words"
)

// SchemaVersion is the version of the Result struct's contract. It mirrors
// the schema_version field of the JSON output produced by the CLI.
const SchemaVersion = audit.SchemaVersion

// CrackTimeEstimate is one attacker scenario applied to a credential's
// entropy. Mirrors the JSON schema's items in crack_time_estimates.
type CrackTimeEstimate struct {
	ProfileID     string
	Description   string
	Seconds       float64
	HumanReadable string
}

// Result is the in-process counterpart of the JSON output schema. Every
// generation function returns a Result whose fields match the JSON
// schema 1:1 (with the password held in memory rather than serialized).
type Result struct {
	SchemaVersion      int
	Password           string
	Length             int
	CharsetID          string
	CharsetSize        int
	EntropyBits        float64
	ExcludedCount      int
	ExcludedSHA256     string
	RequiredClasses    string
	Algorithm          string
	Subcommand         string
	RequestID          string
	TimestampUTC       time.Time
	Warnings           []string
	CrackTimeEstimates []CrackTimeEstimate
}

// EstimateCrackTime returns time-to-break estimates for a credential of
// the given entropy under named attacker profiles. Useful for reporting
// strength in human-readable terms ("3.2 trillion years against a
// nation-state") rather than abstract bits.
//
// Estimates assume uniform random search and may be optimistic against
// dictionary-prone credentials (memorable passphrases, predictable PINs)
// or pessimistic when the verifier uses a strong KDF.
func EstimateCrackTime(entropyBits float64) []CrackTimeEstimate {
	src := policy.EstimateCrackTimes(entropyBits)
	out := make([]CrackTimeEstimate, 0, len(src))
	for _, e := range src {
		out = append(out, CrackTimeEstimate{
			ProfileID:     e.ProfileID,
			Description:   e.Description,
			Seconds:       e.Seconds,
			HumanReadable: e.HumanReadable,
		})
	}
	return out
}

// Errors callers may match with errors.Is.
var (
	ErrBelowEntropyFloor = policy.ErrBelowEntropyFloor
	ErrClassesImpossible = policy.ErrClassesImpossible
	ErrClassExhausted    = generator.ErrClassExhausted
	ErrEntropyFailure    = generator.ErrEntropyFailure
)

// PasswordOptions controls the Password function. All fields are optional;
// zero values yield the same defaults as the `secretgenerator password` CLI
// invocation.
type PasswordOptions struct {
	Length          int     // default 20
	CharsetID       string  // default "alphanum-v1"
	Exclude         string  // optional runes to remove from the charset before generation
	RequiredClasses string  // comma-separated: "lower,upper,digit,symbol"
	MinEntropyBits  float64 // default 80; 0 disables
	AllowWeak       bool    // permit below-floor with a warning
}

// Password generates a random password using a named charset. See
// PasswordOptions for the available knobs and CharsetIDs() for the list
// of valid charset identifiers.
func Password(o PasswordOptions) (Result, error) {
	if o.Length == 0 {
		o.Length = 20
	}
	if o.CharsetID == "" {
		o.CharsetID = "alphanum-v1"
	}
	if o.MinEntropyBits == 0 {
		o.MinEntropyBits = 80
	}

	cs, err := charset.Get(o.CharsetID)
	if err != nil {
		return Result{}, err
	}

	excludedCount, excludedSHA := 0, ""
	if o.Exclude != "" {
		excludedCount = len([]rune(o.Exclude))
		excludedSHA = audit.SHA256Hex(o.Exclude)
		cs, err = charset.Exclude(cs, []rune(o.Exclude))
		if err != nil {
			return Result{}, err
		}
	}

	required, err := policy.ParseClasses(o.RequiredClasses)
	if err != nil {
		return Result{}, err
	}
	if validateErr := policy.ValidateClassesAchievable(cs, o.Length, required); validateErr != nil {
		return Result{}, validateErr
	}

	bits := policy.EntropyBits(o.Length, cs.Size())
	var warnings []string
	if floorErr := policy.EnforceFloor(bits, o.MinEntropyBits, o.AllowWeak); floorErr != nil {
		return Result{}, floorErr
	}
	if o.MinEntropyBits > 0 && bits < o.MinEntropyBits && o.AllowWeak {
		warnings = append(warnings, fmt.Sprintf(
			"entropy %.2f bits below floor %.2f (AllowWeak set)", bits, o.MinEntropyBits))
	}

	pw, err := generator.Generate(generator.Request{
		Charset:         cs,
		Length:          o.Length,
		RequiredClasses: required,
	})
	if err != nil {
		return Result{}, err
	}

	requestID, err := audit.NewUUIDv4(nil)
	if err != nil {
		return Result{}, err
	}
	return Result{
		SchemaVersion:   SchemaVersion,
		Password:        pw,
		Length:          o.Length,
		CharsetID:       cs.ID,
		CharsetSize:     cs.Size(),
		EntropyBits:     bits,
		ExcludedCount:   excludedCount,
		ExcludedSHA256:  excludedSHA,
		RequiredClasses: policy.ClassesString(required),
		Algorithm:       "crypto/rand+rejection-sampling",
		Subcommand:      "password",
		RequestID:       requestID,
		TimestampUTC:    time.Now().UTC(),
		Warnings:        warnings,
	}, nil
}

// SecretOptions controls the Secret function. Default is 32 bytes
// (256 bits) encoded as URL-safe base64 without padding — the
// recommended primitive for machine-to-machine credentials.
type SecretOptions struct {
	Bytes          int     // default 32
	Encoding       string  // default "base64url"; one of base64url|base64|base32|hex
	Prefix         string  // optional fixed prefix (does not contribute to entropy)
	MinEntropyBits float64 // default 128; 0 disables
	AllowWeak      bool
}

// Secret generates a high-entropy machine-readable secret. Recommended for
// AI agents and machine-to-machine systems.
func Secret(o SecretOptions) (Result, error) {
	if o.Bytes == 0 {
		o.Bytes = 32
	}
	if o.Encoding == "" {
		o.Encoding = "base64url"
	}
	if o.MinEntropyBits == 0 {
		o.MinEntropyBits = 128
	}

	if !validEncoding(o.Encoding) {
		return Result{}, fmt.Errorf("secretgen: unknown encoding %q", o.Encoding)
	}
	if o.Bytes < 0 {
		return Result{}, fmt.Errorf("secretgen: bytes must be > 0, got %d", o.Bytes)
	}

	bits := float64(o.Bytes) * 8
	var warnings []string
	if err := policy.EnforceFloor(bits, o.MinEntropyBits, o.AllowWeak); err != nil {
		return Result{}, err
	}
	if o.MinEntropyBits > 0 && bits < o.MinEntropyBits && o.AllowWeak {
		warnings = append(warnings, fmt.Sprintf(
			"entropy %.2f bits below floor %.2f (AllowWeak set)", bits, o.MinEntropyBits))
	}

	raw := make([]byte, o.Bytes)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return Result{}, fmt.Errorf("%w: %w", ErrEntropyFailure, err)
	}
	encoded := encodeBytes(raw, o.Encoding)
	zeroize(raw)
	secret := o.Prefix + encoded

	requestID, err := audit.NewUUIDv4(nil)
	if err != nil {
		return Result{}, err
	}
	return Result{
		SchemaVersion: SchemaVersion,
		Password:      secret,
		Length:        len(secret),
		CharsetID:     "secret-bytes:" + o.Encoding,
		CharsetSize:   256,
		EntropyBits:   bits,
		Algorithm:     "crypto/rand:bytes+" + o.Encoding,
		Subcommand:    "secret",
		RequestID:     requestID,
		TimestampUTC:  time.Now().UTC(),
		Warnings:      warnings,
	}, nil
}

// APIKeyOptions controls the APIKey function. Defaults follow the
// Stripe/GitHub convention: "<prefix><separator><base62-secret>" with
// the secret body sized to ~190 bits of entropy.
type APIKeyOptions struct {
	Prefix         string  // default "sk"
	Separator      string  // default "_"
	Length         int     // default 32; length of the base62 body
	MinEntropyBits float64 // default 128
	AllowWeak      bool
}

// APIKey generates a token with a fixed prefix and a base62 random body
// matching the convention used by Stripe, GitHub, Slack, and Anthropic.
func APIKey(o APIKeyOptions) (Result, error) {
	if o.Prefix == "" {
		o.Prefix = "sk"
	}
	if o.Separator == "" {
		o.Separator = "_"
	}
	if o.Length == 0 {
		o.Length = 32
	}
	if o.MinEntropyBits == 0 {
		o.MinEntropyBits = 128
	}
	if strings.ContainsAny(o.Prefix, " \t\n\r") {
		return Result{}, fmt.Errorf("secretgen: prefix must not contain whitespace")
	}

	cs, err := charset.Get("base62-v1")
	if err != nil {
		return Result{}, err
	}
	bits := policy.EntropyBits(o.Length, cs.Size())
	var warnings []string
	if floorErr := policy.EnforceFloor(bits, o.MinEntropyBits, o.AllowWeak); floorErr != nil {
		return Result{}, floorErr
	}
	if o.MinEntropyBits > 0 && bits < o.MinEntropyBits && o.AllowWeak {
		warnings = append(warnings, fmt.Sprintf(
			"entropy %.2f bits below floor %.2f (AllowWeak set)", bits, o.MinEntropyBits))
	}

	body, err := generator.Generate(generator.Request{Charset: cs, Length: o.Length})
	if err != nil {
		return Result{}, err
	}
	requestID, err := audit.NewUUIDv4(nil)
	if err != nil {
		return Result{}, err
	}
	return Result{
		SchemaVersion: SchemaVersion,
		Password:      o.Prefix + o.Separator + body,
		Length:        o.Length,
		CharsetID:     cs.ID,
		CharsetSize:   cs.Size(),
		EntropyBits:   bits,
		Algorithm:     "crypto/rand+base62",
		Subcommand:    "api-key",
		RequestID:     requestID,
		TimestampUTC:  time.Now().UTC(),
		Warnings:      warnings,
	}, nil
}

// PassphraseOptions controls the Passphrase function. Defaults: 8 EFF
// Large Wordlist words (~103 bits of entropy) joined with a hyphen.
type PassphraseOptions struct {
	Words          int     // default 8
	Separator      string  // default "-"
	Capitalize     bool    // compatibility flag — emits a warning
	DigitSuffix    bool    // compatibility flag — emits a warning
	MinEntropyBits float64 // default 80
	AllowWeak      bool
}

// Passphrase generates a diceware passphrase from the EFF Large Wordlist.
func Passphrase(o PassphraseOptions) (Result, error) {
	if o.Words == 0 {
		o.Words = 8
	}
	if o.Separator == "" {
		o.Separator = "-"
	}
	if o.MinEntropyBits == 0 {
		o.MinEntropyBits = 80
	}

	wordsBits := float64(o.Words) * words.EFFLargeBitsPerWord
	digitBits := 0.0
	if o.DigitSuffix {
		digitBits = 3.321928094887362
	}
	bits := wordsBits + digitBits

	var warnings []string
	if err := policy.EnforceFloor(bits, o.MinEntropyBits, o.AllowWeak); err != nil {
		return Result{}, err
	}
	if o.MinEntropyBits > 0 && bits < o.MinEntropyBits && o.AllowWeak {
		warnings = append(warnings, fmt.Sprintf(
			"entropy %.2f bits below floor %.2f (AllowWeak set)", bits, o.MinEntropyBits))
	}
	if o.Capitalize {
		warnings = append(warnings,
			"Capitalize is a compatibility flag; predictable Title-Case is in every Hashcat ruleset and adds ~0 bits against real attackers (prefer adding a word)")
	}
	if o.DigitSuffix {
		warnings = append(warnings,
			"DigitSuffix is a compatibility flag; appended digits are the #1 attacked transformation. Prefer adding a word (+12.92 bits) over a digit (+3.32 bits)")
	}

	picked, err := words.PickEFFLarge(o.Words, nil)
	if err != nil {
		return Result{}, err
	}
	if o.Capitalize {
		for i, w := range picked {
			picked[i] = capitalizeFirst(w)
		}
	}
	phrase := strings.Join(picked, o.Separator)
	if o.DigitSuffix {
		idx, digitErr := rand.Int(rand.Reader, big.NewInt(10))
		if digitErr != nil {
			return Result{}, fmt.Errorf("%w: digit suffix: %w", ErrEntropyFailure, digitErr)
		}
		phrase += fmt.Sprintf("%d", idx.Int64())
	}

	requestID, err := audit.NewUUIDv4(nil)
	if err != nil {
		return Result{}, err
	}
	return Result{
		SchemaVersion: SchemaVersion,
		Password:      phrase,
		Length:        o.Words,
		CharsetID:     "eff-large-v1",
		CharsetSize:   words.EFFLargeWordCount,
		EntropyBits:   bits,
		Algorithm:     "diceware/eff-large-v1",
		Subcommand:    "passphrase",
		RequestID:     requestID,
		TimestampUTC:  time.Now().UTC(),
		Warnings:      warnings,
	}, nil
}

// CharsetIDs returns the list of named charset identifiers accepted by
// PasswordOptions.CharsetID. The slice is unsorted; callers should sort
// if presenting to humans.
func CharsetIDs() []string {
	return charset.IDs()
}

// helpers

func validEncoding(e string) bool {
	switch e {
	case "base64url", "base64", "base32", "hex":
		return true
	}
	return false
}

func encodeBytes(raw []byte, e string) string {
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
	panic("unreachable")
}

func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
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

// Sentinel for documentation: errors.Is users can chain to underlying errors.
var _ = errors.Is
