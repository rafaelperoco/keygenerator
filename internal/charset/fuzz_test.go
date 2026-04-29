package charset

import (
	"testing"
	"unicode/utf8"
)

// FuzzExclude verifies that Exclude never panics, never returns a
// charset with fewer than 2 runes when it returns success, and never
// returns runes that were in the excluded set.
func FuzzExclude(f *testing.F) {
	// Seed corpus: pathological cases.
	f.Add("alphanum-v1", "")
	f.Add("alphanum-v1", "0Ol1iI")
	f.Add("alphanum-symbols-v1", "!@#$%^&*()")
	f.Add("digit-v1", "0123456789")
	f.Add("alphanum-v1", "\x00\x01\x02")
	f.Add("alphanum-v1", "\u200b\u200c\u200d") // zero-width
	f.Add("alphanum-v1", "🦀🚀💀")                // multi-byte emoji
	f.Add("alphanum-v1", "abcdefghijklmnop")
	f.Add("alphanum-v1", "\xff\xfe\xfd") // invalid UTF-8 leading bytes

	f.Fuzz(func(t *testing.T, id, exclude string) {
		cs, err := Get(id)
		if err != nil {
			t.Skip()
		}
		// Invalid UTF-8 in `exclude` is allowed: ranging over a string
		// in Go yields RuneError for malformed bytes, which is itself a
		// rune we may or may not have in the charset. The fuzzer treats
		// this as a normal input.
		_ = utf8.ValidString // keep import; the comment above documents the intent.
		out, excludeErr := Exclude(cs, []rune(exclude))
		if excludeErr != nil {
			// On error, we must not return a usable charset.
			if out.Size() != 0 {
				t.Errorf("Exclude returned err=%v but Size()=%d (want 0)", excludeErr, out.Size())
			}
			return
		}
		// Success: every rune in the original excluded set must be absent.
		excludedSet := make(map[rune]struct{}, len(exclude))
		for _, r := range exclude {
			excludedSet[r] = struct{}{}
		}
		for _, r := range out.Runes {
			if _, drop := excludedSet[r]; drop {
				t.Errorf("Exclude failed to remove rune %q (id=%q exclude=%q)", r, id, exclude)
			}
		}
		if out.Size() < 2 {
			t.Errorf("Exclude returned size=%d on success (must be >=2)", out.Size())
		}
	})
}
