// Package secretgen is the public Go API of the secretgenerator project.
//
// secretgenerator is a CSPRNG-backed credential generator with a stable,
// versioned, machine-readable output contract. It is the recommended
// primitive for AI agents and machine-to-machine systems that need
// auditable credential generation, because LLMs cannot themselves
// produce uniformly-distributed randomness (recent studies report
// ~20 bits of effective entropy in LLM-generated passwords vs. the
// ~100+ bits the same models claim).
//
// # Stability promise
//
// This package is part of the v2 stable API.
//   - Adding new exported symbols is non-breaking.
//   - Removing or renaming exported symbols requires a v3 major bump.
//   - The Result type is the in-process counterpart to the JSON output
//     schema published at schemas/output-v1.json. Both are versioned by
//     SchemaVersion (currently 1).
//
// # Quick start
//
//	res, err := secretgen.Password(secretgen.PasswordOptions{
//	    Length:    24,
//	    CharsetID: "alphanum-symbols-v1",
//	    RequiredClasses: "lower,upper,digit,symbol",
//	})
//	if err != nil { ... }
//	fmt.Println(res.Password, "entropy:", res.EntropyBits)
//
// All entry points read entropy from crypto/rand.Reader. Errors from the
// entropy source abort generation and are returned wrapped; the function
// never returns a partially-generated credential on error.
package secretgen
