package charset

import (
	"strings"
	"testing"
)

func TestGet_KnownIDs(t *testing.T) {
	for _, id := range IDs() {
		t.Run(id, func(t *testing.T) {
			c, err := Get(id)
			if err != nil {
				t.Fatalf("Get(%q) returned error: %v", id, err)
			}
			if c.ID != id {
				t.Errorf("Get(%q).ID = %q, want %q", id, c.ID, id)
			}
			if c.Size() < 2 {
				t.Errorf("Get(%q).Size() = %d, want >= 2", id, c.Size())
			}
		})
	}
}

func TestGet_UnknownID(t *testing.T) {
	if _, err := Get("does-not-exist"); err == nil {
		t.Fatal("Get(unknown) returned nil error, want error")
	}
}

func TestRegistry_NoDuplicateRunes(t *testing.T) {
	for _, id := range IDs() {
		t.Run(id, func(t *testing.T) {
			c, _ := Get(id)
			seen := make(map[rune]struct{}, len(c.Runes))
			for _, r := range c.Runes {
				if _, dup := seen[r]; dup {
					t.Errorf("charset %q has duplicate rune %q", id, r)
				}
				seen[r] = struct{}{}
			}
		})
	}
}

func TestRegistry_ClassesMatchRunes(t *testing.T) {
	for _, id := range IDs() {
		t.Run(id, func(t *testing.T) {
			c, _ := Get(id)
			var observed Class
			for _, r := range c.Runes {
				observed |= classOfRune(r)
			}
			if observed != c.Classes {
				t.Errorf("charset %q declares classes=%b but runes yield %b", id, c.Classes, observed)
			}
		})
	}
}

func TestExclude_RemovesRunes(t *testing.T) {
	c, _ := Get("alphanum-v1")
	out, err := Exclude(c, []rune("aeiou"))
	if err != nil {
		t.Fatalf("Exclude returned error: %v", err)
	}
	for _, r := range "aeiou" {
		if out.Contains(r) {
			t.Errorf("Exclude did not remove %q", r)
		}
	}
	if got, want := out.Size(), c.Size()-5; got != want {
		t.Errorf("Exclude size = %d, want %d", got, want)
	}
	if !strings.HasSuffix(out.ID, "+excluded") {
		t.Errorf("Exclude ID = %q, want suffix %q", out.ID, "+excluded")
	}
}

func TestExclude_EmptyIsNoop(t *testing.T) {
	c, _ := Get("alphanum-v1")
	out, err := Exclude(c, nil)
	if err != nil {
		t.Fatalf("Exclude(nil) returned error: %v", err)
	}
	if out.ID != c.ID {
		t.Errorf("Exclude(nil).ID = %q, want %q", out.ID, c.ID)
	}
	if out.Size() != c.Size() {
		t.Errorf("Exclude(nil).Size = %d, want %d", out.Size(), c.Size())
	}
}

func TestExclude_TooFewRunesRemaining(t *testing.T) {
	c, _ := Get("digit-v1")
	if _, err := Exclude(c, []rune("0123456789")); err == nil {
		t.Fatal("Exclude that empties the charset returned nil error")
	}
	if _, err := Exclude(c, []rune("012345678")); err == nil {
		t.Fatal("Exclude leaving 1 rune returned nil error, want error")
	}
}

func TestExclude_RecomputesClasses(t *testing.T) {
	c, _ := Get("alphanum-symbols-v1")
	out, err := Exclude(c, []rune("!@#$%^&*()_+{}|:<>?`~-=[]\\;',./"))
	if err != nil {
		t.Fatalf("Exclude returned error: %v", err)
	}
	if out.Classes&ClassSymbol != 0 {
		t.Errorf("Exclude(symbols) Classes still has ClassSymbol bit: %b", out.Classes)
	}
	if out.Classes&(ClassLower|ClassUpper|ClassDigit) == 0 {
		t.Errorf("Exclude(symbols) Classes lost expected lower/upper/digit: %b", out.Classes)
	}
}

func TestCharset_Contains(t *testing.T) {
	c, _ := Get("digit-v1")
	if !c.Contains('5') {
		t.Error("digit-v1 should contain '5'")
	}
	if c.Contains('a') {
		t.Error("digit-v1 should not contain 'a'")
	}
}

func TestCharset_ClassOf(t *testing.T) {
	c, _ := Get("alphanum-symbols-v1")
	tests := []struct {
		r    rune
		want Class
	}{
		{'a', ClassLower},
		{'Z', ClassUpper},
		{'7', ClassDigit},
		{'!', ClassSymbol},
		{'é', 0}, // not in charset
	}
	for _, tt := range tests {
		if got := c.ClassOf(tt.r); got != tt.want {
			t.Errorf("ClassOf(%q) = %b, want %b", tt.r, got, tt.want)
		}
	}
}
