package policy

import (
	"errors"
	"math"
	"testing"

	"github.com/rafaelperoco/keygenerator/internal/charset"
)

func TestEntropyBits(t *testing.T) {
	tests := []struct {
		length, size int
		want         float64
	}{
		{20, 62, 20 * math.Log2(62)},  // ~119.08
		{12, 94, 12 * math.Log2(94)},  // ~78.66
		{1, 2, 1.0},                   // single bit
		{0, 62, 0},                    // empty length
		{20, 1, 0},                    // degenerate charset
		{20, 0, 0},                    // empty charset
		{-5, 62, 0},                   // negative length
	}
	for _, tt := range tests {
		got := EntropyBits(tt.length, tt.size)
		if math.Abs(got-tt.want) > 1e-9 {
			t.Errorf("EntropyBits(%d,%d) = %v, want %v", tt.length, tt.size, got, tt.want)
		}
	}
}

func TestEnforceFloor(t *testing.T) {
	tests := []struct {
		name      string
		bits      float64
		floor     float64
		allowWeak bool
		wantErr   bool
	}{
		{"floor disabled", 10, 0, false, false},
		{"floor disabled negative", 10, -1, false, false},
		{"above floor", 100, 80, false, false},
		{"exactly at floor", 80, 80, false, false},
		{"below floor strict", 50, 80, false, true},
		{"below floor allow-weak", 50, 80, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := EnforceFloor(tt.bits, tt.floor, tt.allowWeak)
			if (err != nil) != tt.wantErr {
				t.Errorf("EnforceFloor(%v,%v,%v) err=%v wantErr=%v",
					tt.bits, tt.floor, tt.allowWeak, err, tt.wantErr)
			}
			if err != nil && !errors.Is(err, ErrBelowEntropyFloor) {
				t.Errorf("error not wrapping ErrBelowEntropyFloor: %v", err)
			}
		})
	}
}

func TestValidateClassesAchievable(t *testing.T) {
	alphanumSym, _ := charset.Get("alphanum-symbols-v1")
	alphanum, _ := charset.Get("alphanum-v1")
	digit, _ := charset.Get("digit-v1")

	tests := []struct {
		name     string
		cs       charset.Charset
		length   int
		required charset.Class
		wantErr  bool
	}{
		{"no requirements", alphanum, 8, 0, false},
		{"satisfiable", alphanumSym, 4, charset.ClassLower | charset.ClassUpper | charset.ClassDigit | charset.ClassSymbol, false},
		{"missing class symbol", alphanum, 8, charset.ClassSymbol, true},
		{"length too short", alphanumSym, 2, charset.ClassLower | charset.ClassUpper | charset.ClassDigit | charset.ClassSymbol, true},
		{"digit-only with symbol required", digit, 8, charset.ClassSymbol, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateClassesAchievable(tt.cs, tt.length, tt.required)
			if (err != nil) != tt.wantErr {
				t.Errorf("err=%v wantErr=%v", err, tt.wantErr)
			}
			if err != nil && !errors.Is(err, ErrClassesImpossible) {
				t.Errorf("error not wrapping ErrClassesImpossible: %v", err)
			}
		})
	}
}

func TestParseClasses(t *testing.T) {
	tests := []struct {
		spec    string
		want    charset.Class
		wantErr bool
	}{
		{"", 0, false},
		{"lower", charset.ClassLower, false},
		{"lower,upper,digit,symbol", charset.ClassLower | charset.ClassUpper | charset.ClassDigit | charset.ClassSymbol, false},
		{"upper,upper", charset.ClassUpper, false}, // dedupe via OR
		{"bogus", 0, true},
		{"lower,bogus", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.spec, func(t *testing.T) {
			got, err := ParseClasses(tt.spec)
			if (err != nil) != tt.wantErr {
				t.Errorf("err=%v wantErr=%v", err, tt.wantErr)
			}
			if err == nil && got != tt.want {
				t.Errorf("got %b want %b", got, tt.want)
			}
		})
	}
}

func TestClassesString_CanonicalOrder(t *testing.T) {
	in := charset.ClassSymbol | charset.ClassDigit | charset.ClassUpper | charset.ClassLower
	if got, want := ClassesString(in), "lower,upper,digit,symbol"; got != want {
		t.Errorf("got %q want %q", got, want)
	}
	if got := ClassesString(0); got != "" {
		t.Errorf("ClassesString(0) = %q, want empty", got)
	}
}
