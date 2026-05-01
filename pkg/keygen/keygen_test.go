package keygen

import (
	"errors"
	"strings"
	"testing"
)

func TestPassword_Defaults(t *testing.T) {
	res, err := Password(PasswordOptions{})
	if err != nil {
		t.Fatalf("Password: %v", err)
	}
	if res.Length != 20 {
		t.Errorf("length = %d, want 20", res.Length)
	}
	if res.CharsetID != "alphanum-v1" {
		t.Errorf("charset_id = %q", res.CharsetID)
	}
	if res.SchemaVersion != SchemaVersion {
		t.Errorf("schema_version = %d", res.SchemaVersion)
	}
	if len([]rune(res.Password)) != 20 {
		t.Errorf("password length mismatch: %d", len([]rune(res.Password)))
	}
}

func TestPassword_BelowFloor(t *testing.T) {
	_, err := Password(PasswordOptions{Length: 4})
	if !errors.Is(err, ErrBelowEntropyFloor) {
		t.Errorf("expected ErrBelowEntropyFloor, got %v", err)
	}
}

func TestPassword_AllowWeakWarns(t *testing.T) {
	res, err := Password(PasswordOptions{Length: 4, AllowWeak: true})
	if err != nil {
		t.Fatalf("Password: %v", err)
	}
	if len(res.Warnings) == 0 {
		t.Errorf("expected warning")
	}
}

func TestPassword_RequiredClasses(t *testing.T) {
	res, err := Password(PasswordOptions{
		Length:          16,
		CharsetID:       "alphanum-symbols-v1",
		RequiredClasses: "lower,upper,digit,symbol",
	})
	if err != nil {
		t.Fatalf("Password: %v", err)
	}
	hasL, hasU, hasD, hasS := false, false, false, false
	for _, r := range res.Password {
		switch {
		case r >= 'a' && r <= 'z':
			hasL = true
		case r >= 'A' && r <= 'Z':
			hasU = true
		case r >= '0' && r <= '9':
			hasD = true
		default:
			hasS = true
		}
	}
	if !hasL || !hasU || !hasD || !hasS {
		t.Errorf("missing classes in %q", res.Password)
	}
}

func TestPassword_ImpossibleClasses(t *testing.T) {
	_, err := Password(PasswordOptions{
		Length:          8,
		CharsetID:       "digit-v1",
		RequiredClasses: "symbol",
		MinEntropyBits:  -1, // disable floor
	})
	if !errors.Is(err, ErrClassesImpossible) {
		t.Errorf("expected ErrClassesImpossible, got %v", err)
	}
}

func TestPassword_UnknownCharset(t *testing.T) {
	_, err := Password(PasswordOptions{CharsetID: "no-such"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestPassword_ExcludeBugFixed(t *testing.T) {
	res, err := Password(PasswordOptions{
		Length:  20,
		Exclude: "abcdefghijklmnopqrstuvwxyz",
	})
	if err != nil {
		t.Fatalf("Password: %v", err)
	}
	if len([]rune(res.Password)) != 20 {
		t.Errorf("length = %d, want 20", len([]rune(res.Password)))
	}
	for _, r := range res.Password {
		if r >= 'a' && r <= 'z' {
			t.Errorf("excluded rune %q present", r)
		}
	}
	if res.ExcludedCount != 26 {
		t.Errorf("excluded_count = %d, want 26", res.ExcludedCount)
	}
}

func TestSecret_Defaults(t *testing.T) {
	res, err := Secret(SecretOptions{})
	if err != nil {
		t.Fatalf("Secret: %v", err)
	}
	if res.Length != 43 {
		t.Errorf("length = %d, want 43 (32 bytes base64url no padding)", res.Length)
	}
	if res.EntropyBits != 256 {
		t.Errorf("entropy_bits = %v, want 256", res.EntropyBits)
	}
}

func TestSecret_AllEncodings(t *testing.T) {
	for _, enc := range []string{"base64url", "base64", "base32", "hex"} {
		t.Run(enc, func(t *testing.T) {
			res, err := Secret(SecretOptions{Bytes: 16, Encoding: enc, MinEntropyBits: -1})
			if err != nil {
				t.Fatalf("Secret(%q): %v", enc, err)
			}
			if !strings.Contains(res.CharsetID, enc) {
				t.Errorf("charset_id = %q does not include %q", res.CharsetID, enc)
			}
		})
	}
}

func TestSecret_UnknownEncoding(t *testing.T) {
	_, err := Secret(SecretOptions{Encoding: "rot13"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestSecret_NegativeBytes(t *testing.T) {
	_, err := Secret(SecretOptions{Bytes: -1})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestSecret_BelowFloor(t *testing.T) {
	_, err := Secret(SecretOptions{Bytes: 8})
	if !errors.Is(err, ErrBelowEntropyFloor) {
		t.Errorf("expected ErrBelowEntropyFloor, got %v", err)
	}
}

func TestSecret_Prefix(t *testing.T) {
	res, err := Secret(SecretOptions{Prefix: "sk_"})
	if err != nil {
		t.Fatalf("Secret: %v", err)
	}
	if !strings.HasPrefix(res.Password, "sk_") {
		t.Errorf("password %q missing prefix", res.Password)
	}
}

func TestAPIKey_Defaults(t *testing.T) {
	res, err := APIKey(APIKeyOptions{})
	if err != nil {
		t.Fatalf("APIKey: %v", err)
	}
	if !strings.HasPrefix(res.Password, "sk_") {
		t.Errorf("password %q missing default sk_ prefix", res.Password)
	}
	if res.CharsetID != "base62-v1" {
		t.Errorf("charset_id = %q", res.CharsetID)
	}
}

func TestAPIKey_PrefixWhitespace(t *testing.T) {
	_, err := APIKey(APIKeyOptions{Prefix: "sk live"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestAPIKey_Custom(t *testing.T) {
	res, err := APIKey(APIKeyOptions{Prefix: "ghp", Separator: "_", Length: 40})
	if err != nil {
		t.Fatalf("APIKey: %v", err)
	}
	if !strings.HasPrefix(res.Password, "ghp_") {
		t.Errorf("password %q missing prefix", res.Password)
	}
}

func TestPassphrase_Defaults(t *testing.T) {
	res, err := Passphrase(PassphraseOptions{})
	if err != nil {
		t.Fatalf("Passphrase: %v", err)
	}
	parts := strings.Split(res.Password, "-")
	if len(parts) != 8 {
		t.Errorf("got %d words, want 8", len(parts))
	}
	if res.CharsetID != "eff-large-v1" {
		t.Errorf("charset_id = %q", res.CharsetID)
	}
}

func TestPassphrase_BelowFloor(t *testing.T) {
	_, err := Passphrase(PassphraseOptions{Words: 5})
	if !errors.Is(err, ErrBelowEntropyFloor) {
		t.Errorf("expected ErrBelowEntropyFloor, got %v", err)
	}
}

func TestPassphrase_DigitSuffixWarns(t *testing.T) {
	res, err := Passphrase(PassphraseOptions{DigitSuffix: true})
	if err != nil {
		t.Fatalf("Passphrase: %v", err)
	}
	last := res.Password[len(res.Password)-1]
	if last < '0' || last > '9' {
		t.Errorf("password %q does not end with digit", res.Password)
	}
	if len(res.Warnings) == 0 {
		t.Errorf("expected DigitSuffix warning")
	}
}

func TestPassphrase_CapitalizeWarns(t *testing.T) {
	res, err := Passphrase(PassphraseOptions{Capitalize: true})
	if err != nil {
		t.Fatalf("Passphrase: %v", err)
	}
	for _, w := range strings.Split(res.Password, "-") {
		first := w[0]
		if first < 'A' || first > 'Z' {
			t.Errorf("word %q does not start with uppercase", w)
		}
	}
	if len(res.Warnings) == 0 {
		t.Errorf("expected Capitalize warning")
	}
}

func TestCharsetIDs(t *testing.T) {
	ids := CharsetIDs()
	if len(ids) < 5 {
		t.Errorf("expected several charset ids, got %d", len(ids))
	}
	want := []string{"alphanum-v1", "base62-v1", "hex-v1"}
	have := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		have[id] = struct{}{}
	}
	for _, w := range want {
		if _, ok := have[w]; !ok {
			t.Errorf("missing charset %q in CharsetIDs()", w)
		}
	}
}
