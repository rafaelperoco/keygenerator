package policy

import "testing"

func TestIsWeakPIN_AllSameDigit(t *testing.T) {
	for _, pin := range []string{"00", "0000", "1111", "999999", "55555"} {
		if !IsWeakPIN(pin) {
			t.Errorf("%q should be classified weak (all same)", pin)
		}
	}
}

func TestIsWeakPIN_StrictSequences(t *testing.T) {
	weak := []string{"1234", "0123", "6789", "12345", "9876", "3210", "987654"}
	for _, pin := range weak {
		if !IsWeakPIN(pin) {
			t.Errorf("%q should be weak (strict sequence)", pin)
		}
	}
}

func TestIsWeakPIN_ShortRepetition(t *testing.T) {
	weak := []string{"1212", "121212", "5050", "123123", "456456"}
	for _, pin := range weak {
		if !IsWeakPIN(pin) {
			t.Errorf("%q should be weak (short repetition)", pin)
		}
	}
}

func TestIsWeakPIN_TopCommon(t *testing.T) {
	for pin := range commonPINBlocklist {
		if !IsWeakPIN(pin) {
			t.Errorf("blocklisted PIN %q passed weak check", pin)
		}
	}
}

func TestIsWeakPIN_CalendarYears(t *testing.T) {
	for _, pin := range []string{"1980", "1999", "2000", "2024", "2099"} {
		if !IsWeakPIN(pin) {
			t.Errorf("%q should be weak (calendar year)", pin)
		}
	}
}

func TestIsWeakPIN_StrongExamples(t *testing.T) {
	strong := []string{
		"4729", // random, not in blocklist
		"7361",
		"8052",
		"903571",
		"816492",
		"3704",
	}
	for _, pin := range strong {
		if IsWeakPIN(pin) {
			t.Errorf("%q should NOT be weak", pin)
		}
	}
}

func TestIsWeakPIN_EdgeCases(t *testing.T) {
	if !IsWeakPIN("") {
		t.Error("empty PIN should be weak")
	}
	if IsWeakPIN("12") {
		t.Error("two-digit non-blocklisted PIN should not be weak (too short for sequence rule)")
	}
	if IsWeakPIN("abcd") {
		t.Error("non-digit input should return false (out of scope)")
	}
	if IsWeakPIN("12a4") {
		t.Error("mixed digit/non-digit should return false")
	}
}

func TestIsWeakPIN_ThreeDigitsNotSequence(t *testing.T) {
	// Three-digit ascending should not be classified as weak by the
	// sequence rule (we require length>=4 to avoid false positives on
	// inherently short patterns).
	if IsWeakPIN("123") {
		t.Error("3-digit sequence should not be weak by sequence rule alone")
	}
}
