package main

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

// codedError pairs a process exit code with an error.
type codedError struct {
	code int
	err  error
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
