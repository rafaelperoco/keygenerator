package audit

// Error code registry. These string identifiers are stable and versioned
// in lockstep with the CLI's exit codes. Agents should branch on Code
// rather than on the integer exit code, both because string codes survive
// a future exit-code reshuffle and because they double as a key into the
// hint table below.
//
// Keep this list in sync with cmd/secretgenerator/exit.go and with
// docs/SCHEMA.md. New codes are additive (non-breaking); changing the
// meaning of an existing code is breaking.
const (
	CodeInvalidArgs     = "E_INVALID_ARGS"
	CodeEntropyTooLow   = "E_ENTROPY_TOO_LOW"
	CodeRNGFailure      = "E_RNG_FAILURE"
	CodeCharsetEmpty    = "E_CHARSET_EMPTY"
	CodeClassImpossible = "E_CLASS_IMPOSSIBLE"
)

// hints maps a stable error code to a one-line remediation suggestion. The
// hint is intentionally short and prescriptive — it tells the caller what
// to change to recover, not why the error happened. Used by the CLI to
// populate Error.Hint.
var hints = map[string]string{
	CodeInvalidArgs:     "check argument names and types; run `--help` to see the accepted shape",
	CodeEntropyTooLow:   "increase --length, choose a richer --charset, or pass --allow-weak (records a warning)",
	CodeRNGFailure:      "the OS entropy source returned an error; retry, and check that /dev/urandom or the equivalent is reachable",
	CodeCharsetEmpty:    "--exclude removed too many runes; relax the exclusion or pick a larger --charset",
	CodeClassImpossible: "--require-classes asks for a class the --charset cannot supply, or --length is shorter than the number of classes; pick a richer charset or longer length",
}

// HintFor returns the curated hint for a known error code, or empty string
// if the code is not in the registry. Callers may use this directly when
// constructing Error{} values.
func HintFor(code string) string {
	return hints[code]
}

// NewError is a small constructor used by the CLI fail() helper. It looks
// up the hint from the registry; callers can override by setting Hint
// after construction.
func NewError(code, message string) *Error {
	return &Error{
		Code:    code,
		Message: message,
		Hint:    hints[code],
	}
}
