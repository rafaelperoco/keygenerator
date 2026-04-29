package charset

// Versioned charset registry. Adding new charsets is non-breaking; modifying
// the runes behind an existing ID is breaking and requires a new "-vN" suffix.
var registry = map[string]Charset{
	"lower-v1": {
		ID:      "lower-v1",
		Runes:   []rune("abcdefghijklmnopqrstuvwxyz"),
		Classes: ClassLower,
	},
	"upper-v1": {
		ID:      "upper-v1",
		Runes:   []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
		Classes: ClassUpper,
	},
	"digit-v1": {
		ID:      "digit-v1",
		Runes:   []rune("0123456789"),
		Classes: ClassDigit,
	},
	"symbol-v1": {
		ID:      "symbol-v1",
		Runes:   []rune("!@#$%^&*()_+{}|:<>?`~-=[]\\;',./"),
		Classes: ClassSymbol,
	},
	"alpha-v1": {
		ID:      "alpha-v1",
		Runes:   []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"),
		Classes: ClassLower | ClassUpper,
	},
	"alphanum-v1": {
		ID:      "alphanum-v1",
		Runes:   []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"),
		Classes: ClassLower | ClassUpper | ClassDigit,
	},
	"alphanum-symbols-v1": {
		ID:      "alphanum-symbols-v1",
		Runes:   []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+{}|:<>?`~-=[]\\;',./"),
		Classes: ClassLower | ClassUpper | ClassDigit | ClassSymbol,
	},
	"numeric-v1": {
		ID:      "numeric-v1",
		Runes:   []rune("0123456789"),
		Classes: ClassDigit,
	},
	"hex-v1": {
		ID:      "hex-v1",
		Runes:   []rune("0123456789abcdef"),
		Classes: ClassLower | ClassDigit,
	},
	"base62-v1": {
		ID:      "base62-v1",
		Runes:   []rune("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"),
		Classes: ClassLower | ClassUpper | ClassDigit,
	},
}

// IDs returns the registered charset IDs (sorted is not guaranteed).
func IDs() []string {
	out := make([]string, 0, len(registry))
	for id := range registry {
		out = append(out, id)
	}
	return out
}
