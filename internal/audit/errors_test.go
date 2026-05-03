package audit

import "testing"

func TestNewError_KnownCode(t *testing.T) {
	e := NewError(CodeEntropyTooLow, "policy: 23.82 bits < 80")
	if e.Code != CodeEntropyTooLow {
		t.Errorf("Code = %q, want %q", e.Code, CodeEntropyTooLow)
	}
	if e.Message != "policy: 23.82 bits < 80" {
		t.Errorf("Message = %q", e.Message)
	}
	if e.Hint == "" {
		t.Errorf("Hint should be populated for known code")
	}
}

func TestNewError_UnknownCode(t *testing.T) {
	e := NewError("E_DOES_NOT_EXIST", "synthetic")
	if e.Code != "E_DOES_NOT_EXIST" {
		t.Errorf("Code = %q", e.Code)
	}
	if e.Hint != "" {
		t.Errorf("Hint should be empty for unknown code, got %q", e.Hint)
	}
}

func TestHintFor_Coverage(t *testing.T) {
	codes := []string{
		CodeInvalidArgs,
		CodeEntropyTooLow,
		CodeRNGFailure,
		CodeCharsetEmpty,
		CodeClassImpossible,
	}
	for _, c := range codes {
		if HintFor(c) == "" {
			t.Errorf("registry missing hint for %q", c)
		}
	}
	if HintFor("E_NOPE") != "" {
		t.Errorf("HintFor(unknown) should return empty string")
	}
}
