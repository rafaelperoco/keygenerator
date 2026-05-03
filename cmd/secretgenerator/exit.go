package main

import "github.com/rafaelperoco/secretgenerator/internal/audit"

// Exit codes form part of the CLI public contract. Documented in
// docs/SCHEMA.md and tested in test/e2e.
const (
	ExitOK              = 0
	ExitInvalidArgs     = 2
	ExitEntropyTooLow   = 3
	ExitRNGFailure      = 4
	ExitCharsetEmpty    = 5
	ExitClassImpossible = 6
)

// exitToCode maps the process exit code to the stable string identifier
// used in JSON error envelopes. Agents should branch on the string code
// (E_INVALID_ARGS, etc.) rather than the integer because the strings
// survive future exit-code reshuffles and double as keys into the hint
// table maintained in internal/audit.
func exitToCode(exit int) string {
	switch exit {
	case ExitInvalidArgs:
		return audit.CodeInvalidArgs
	case ExitEntropyTooLow:
		return audit.CodeEntropyTooLow
	case ExitRNGFailure:
		return audit.CodeRNGFailure
	case ExitCharsetEmpty:
		return audit.CodeCharsetEmpty
	case ExitClassImpossible:
		return audit.CodeClassImpossible
	}
	return audit.CodeInvalidArgs
}

// codedError pairs a process exit code with an error.
//
// When jsonEmitted is true, the failing subcommand has already written a
// schema-v1 JSON error envelope to stdout. main() then suppresses the
// default "fmt.Fprintln(stderr, err)" path so the agent sees only the
// structured JSON (the integer exit code is still propagated for
// shell-script callers).
type codedError struct {
	code        int
	err         error
	jsonEmitted bool
}

func (e *codedError) Error() string {
	if e == nil || e.err == nil {
		return ""
	}
	return e.err.Error()
}

func (e *codedError) Unwrap() error { return e.err }

func fail(code int, err error) error {
	if err == nil {
		return nil
	}
	return &codedError{code: code, err: err}
}

// failJSON is the variant subcommands use when they have already emitted a
// JSON error envelope on stdout. main() will not echo the message to
// stderr.
func failJSON(code int, err error) error {
	if err == nil {
		return nil
	}
	return &codedError{code: code, err: err, jsonEmitted: true}
}
