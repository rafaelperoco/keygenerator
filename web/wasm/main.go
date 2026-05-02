// Command wasm builds the secretgenerator core into a WebAssembly module
// for client-side use on secretgenerator.org. It exposes the same
// generation primitives as the CLI through syscall/js bindings; the
// browser-side JavaScript layer wraps the bindings into a Promise-based
// API.
//
// Build:
//
//	tinygo build -o ../public/keygen.wasm -target wasm -no-debug ./wasm
//
// The wasm_exec.js shim that pairs with this binary lives in the TinyGo
// installation at $(tinygo env TINYGOROOT)/targets/wasm_exec.js.
//
// The js build constraint excludes this file from native `go test ./...`
// runs since syscall/js is only available under GOOS=js.

//go:build js && wasm

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"syscall/js"
	"time"

	"github.com/rafaelperoco/secretgenerator/internal/audit"
	"github.com/rafaelperoco/secretgenerator/internal/charset"
	"github.com/rafaelperoco/secretgenerator/internal/generator"
	"github.com/rafaelperoco/secretgenerator/internal/policy"
	"github.com/rafaelperoco/secretgenerator/internal/words"
	"github.com/rafaelperoco/secretgenerator/pkg/secretgen"
)

const browserVersion = "secretgenerator-web@2.0.0"

func main() {
	js.Global().Set("secretgen", js.ValueOf(map[string]any{
		"password":          js.FuncOf(wrapPassword),
		"secret":            js.FuncOf(wrapSecret),
		"passphrase":        js.FuncOf(wrapPassphrase),
		"apiKey":            js.FuncOf(wrapAPIKey),
		"pin":               js.FuncOf(wrapPIN),
		"entropy":           js.FuncOf(wrapEntropy),
		"charsets":          js.FuncOf(wrapCharsets),
		"attackerProfiles":  js.FuncOf(wrapAttackerProfiles),
		"crackTimes":        js.FuncOf(wrapCrackTimes),
		"schemaVersion":     js.ValueOf(audit.SchemaVersion),
		"version":           js.ValueOf(browserVersion),
	}))

	// Block forever; syscall/js callbacks are dispatched on the JS event
	// loop and we must keep the Go runtime alive to serve them.
	select {}
}

// optString reads a string field from a JS object, falling back to def.
func optString(obj js.Value, key, def string) string {
	v := obj.Get(key)
	if v.IsUndefined() || v.IsNull() {
		return def
	}
	return v.String()
}

// optInt reads an int field from a JS object, falling back to def.
func optInt(obj js.Value, key string, def int) int {
	v := obj.Get(key)
	if v.IsUndefined() || v.IsNull() {
		return def
	}
	return v.Int()
}

// optFloat reads a float field from a JS object, falling back to def.
func optFloat(obj js.Value, key string, def float64) float64 {
	v := obj.Get(key)
	if v.IsUndefined() || v.IsNull() {
		return def
	}
	return v.Float()
}

// optBool reads a bool field from a JS object, falling back to def.
func optBool(obj js.Value, key string, def bool) bool {
	v := obj.Get(key)
	if v.IsUndefined() || v.IsNull() {
		return def
	}
	return v.Bool()
}

// resultToJS converts a secretgen.Result into a plain JS object matching
// the JSON schema-v1 shape.
func resultToJS(r secretgen.Result) js.Value {
	m := map[string]any{
		"schema_version":   r.SchemaVersion,
		"password":         r.Password,
		"length":           r.Length,
		"charset_id":       r.CharsetID,
		"charset_size":     r.CharsetSize,
		"entropy_bits":     r.EntropyBits,
		"excluded_count":   r.ExcludedCount,
		"required_classes": r.RequiredClasses,
		"algorithm":        r.Algorithm,
		"subcommand":       r.Subcommand,
		"version":          browserVersion,
		"commit":           "browser",
		"build_date":       "browser",
		"request_id":       r.RequestID,
		"timestamp_utc":    r.TimestampUTC.UTC().Format(time.RFC3339Nano),
	}
	if r.ExcludedSHA256 != "" {
		m["excluded_sha256"] = r.ExcludedSHA256
	}
	if len(r.Warnings) > 0 {
		w := make([]any, len(r.Warnings))
		for i, s := range r.Warnings {
			w[i] = s
		}
		m["warnings"] = w
	}
	return js.ValueOf(m)
}

// errToJS wraps a Go error into a {error: "..."} JS object so the JS layer
// can branch on a single shape.
func errToJS(err error) js.Value {
	return js.ValueOf(map[string]any{"error": err.Error()})
}

// wrapPassword binds secretgen.Password to JS. Expects a single object arg
// matching PasswordOptions; missing fields take defaults.
func wrapPassword(_ js.Value, args []js.Value) any {
	if len(args) == 0 {
		return errToJS(errors.New("password: missing options object"))
	}
	o := args[0]
	res, err := secretgen.Password(secretgen.PasswordOptions{
		Length:          optInt(o, "length", 0),
		CharsetID:       optString(o, "charsetId", ""),
		Exclude:         optString(o, "exclude", ""),
		RequiredClasses: optString(o, "requiredClasses", ""),
		MinEntropyBits:  optFloat(o, "minEntropyBits", 0),
		AllowWeak:       optBool(o, "allowWeak", false),
	})
	if err != nil {
		return errToJS(err)
	}
	return resultToJS(res)
}

func wrapSecret(_ js.Value, args []js.Value) any {
	if len(args) == 0 {
		return errToJS(errors.New("secret: missing options object"))
	}
	o := args[0]
	res, err := secretgen.Secret(secretgen.SecretOptions{
		Bytes:          optInt(o, "bytes", 0),
		Encoding:       optString(o, "encoding", ""),
		Prefix:         optString(o, "prefix", ""),
		MinEntropyBits: optFloat(o, "minEntropyBits", 0),
		AllowWeak:      optBool(o, "allowWeak", false),
	})
	if err != nil {
		return errToJS(err)
	}
	return resultToJS(res)
}

func wrapPassphrase(_ js.Value, args []js.Value) any {
	if len(args) == 0 {
		return errToJS(errors.New("passphrase: missing options object"))
	}
	o := args[0]
	res, err := secretgen.Passphrase(secretgen.PassphraseOptions{
		Words:          optInt(o, "words", 0),
		Separator:      optString(o, "separator", ""),
		Capitalize:     optBool(o, "capitalize", false),
		DigitSuffix:    optBool(o, "digitSuffix", false),
		MinEntropyBits: optFloat(o, "minEntropyBits", 0),
		AllowWeak:      optBool(o, "allowWeak", false),
	})
	if err != nil {
		return errToJS(err)
	}
	return resultToJS(res)
}

func wrapAPIKey(_ js.Value, args []js.Value) any {
	if len(args) == 0 {
		return errToJS(errors.New("apiKey: missing options object"))
	}
	o := args[0]
	res, err := secretgen.APIKey(secretgen.APIKeyOptions{
		Prefix:         optString(o, "prefix", ""),
		Separator:      optString(o, "separator", ""),
		Length:         optInt(o, "length", 0),
		MinEntropyBits: optFloat(o, "minEntropyBits", 0),
		AllowWeak:      optBool(o, "allowWeak", false),
	})
	if err != nil {
		return errToJS(err)
	}
	return resultToJS(res)
}

// wrapPIN reimplements the CLI pin subcommand for browser use.
// secretgen package does not expose a Pin function (the CLI bakes the
// safety gate); we replicate the gate here for parity.
func wrapPIN(_ js.Value, args []js.Value) any {
	if len(args) == 0 {
		return errToJS(errors.New("pin: missing options object"))
	}
	o := args[0]
	digits := optInt(o, "digits", 6)
	if digits < 4 {
		return errToJS(fmt.Errorf("pin: digits must be >= 4, got %d", digits))
	}
	if !optBool(o, "acknowledgeLowEntropy", false) {
		return errToJS(fmt.Errorf("pin: requires acknowledgeLowEntropy=true (PINs are intrinsically low-entropy)"))
	}
	allowWeakPattern := optBool(o, "allowWeakPattern", false)

	cs, err := charset.Get("digit-v1")
	if err != nil {
		return errToJS(err)
	}
	var pin string
	const maxRetries = 100
	for attempt := 0; attempt < maxRetries; attempt++ {
		candidate, gerr := generator.Generate(generator.Request{Charset: cs, Length: digits})
		if gerr != nil {
			return errToJS(gerr)
		}
		if allowWeakPattern || !policy.IsWeakPIN(candidate) {
			pin = candidate
			break
		}
		if attempt == maxRetries-1 {
			return errToJS(fmt.Errorf("pin: could not produce a strong-pattern PIN after %d attempts", maxRetries))
		}
	}

	bits := policy.EntropyBits(digits, 10)
	requestID, err := audit.NewUUIDv4(nil)
	if err != nil {
		return errToJS(err)
	}
	res := secretgen.Result{
		SchemaVersion: audit.SchemaVersion,
		Password:      pin,
		Length:        digits,
		CharsetID:     cs.ID,
		CharsetSize:   cs.Size(),
		EntropyBits:   bits,
		Algorithm:     "crypto/rand+weak-pin-rejection",
		Subcommand:    "pin",
		RequestID:     requestID,
		TimestampUTC:  time.Now().UTC(),
		Warnings: []string{
			fmt.Sprintf("PIN entropy is %.1f bits; safe only with verifier-side rate limiting", bits),
		},
	}
	return resultToJS(res)
}

// wrapEntropy estimates the entropy of an existing password supplied
// via {password: "..."}. Output schema mirrors the CLI entropy
// subcommand but lives entirely client-side.
func wrapEntropy(_ js.Value, args []js.Value) any {
	if len(args) == 0 {
		return errToJS(errors.New("entropy: missing options object"))
	}
	o := args[0]
	pw := optString(o, "password", "")
	if pw == "" {
		return errToJS(errors.New("entropy: password is empty"))
	}

	classes := observeClasses(pw)
	size := classSize(classes)
	bits := policy.EntropyBits(len(pw), size)

	requestID, err := audit.NewUUIDv4(nil)
	if err != nil {
		return errToJS(err)
	}
	res := secretgen.Result{
		SchemaVersion:   audit.SchemaVersion,
		Length:          len(pw),
		CharsetID:       inferCharsetID(classes),
		CharsetSize:     size,
		EntropyBits:     bits,
		RequiredClasses: policy.ClassesString(classes),
		Algorithm:       "shannon-upper-bound",
		Subcommand:      "entropy",
		RequestID:       requestID,
		TimestampUTC:    time.Now().UTC(),
	}
	return resultToJS(res)
}

func observeClasses(s string) charset.Class {
	var c charset.Class
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			c |= charset.ClassLower
		case r >= 'A' && r <= 'Z':
			c |= charset.ClassUpper
		case r >= '0' && r <= '9':
			c |= charset.ClassDigit
		default:
			c |= charset.ClassSymbol
		}
	}
	return c
}

func classSize(c charset.Class) int {
	size := 0
	if c&charset.ClassLower != 0 {
		size += 26
	}
	if c&charset.ClassUpper != 0 {
		size += 26
	}
	if c&charset.ClassDigit != 0 {
		size += 10
	}
	if c&charset.ClassSymbol != 0 {
		size += 32
	}
	return size
}

func inferCharsetID(c charset.Class) string {
	parts := []string{}
	if c&charset.ClassLower != 0 {
		parts = append(parts, "lower")
	}
	if c&charset.ClassUpper != 0 {
		parts = append(parts, "upper")
	}
	if c&charset.ClassDigit != 0 {
		parts = append(parts, "digit")
	}
	if c&charset.ClassSymbol != 0 {
		parts = append(parts, "symbol")
	}
	if len(parts) == 0 {
		return "empty"
	}
	return "observed:" + strings.Join(parts, "+")
}

// wrapCharsets returns the list of named charset IDs available to the
// password subcommand.
func wrapCharsets(_ js.Value, _ []js.Value) any {
	ids := secretgen.CharsetIDs()
	out := make([]any, len(ids))
	for i, id := range ids {
		out[i] = id
	}
	return js.ValueOf(out)
}

// wrapAttackerProfiles returns the named attacker profiles used to
// estimate crack times.
func wrapAttackerProfiles(_ js.Value, _ []js.Value) any {
	out := make([]any, len(policy.AttackerProfiles))
	for i, p := range policy.AttackerProfiles {
		out[i] = map[string]any{
			"id":                  p.ID,
			"description":         p.Description,
			"guesses_per_second":  p.GuessesPerSec,
		}
	}
	return js.ValueOf(out)
}

// wrapCrackTimes returns time-to-break estimates for a given entropy
// across all attacker profiles.
func wrapCrackTimes(_ js.Value, args []js.Value) any {
	if len(args) == 0 {
		return errToJS(errors.New("crackTimes: missing entropy bits argument"))
	}
	bits := args[0].Float()
	estimates := policy.EstimateCrackTimes(bits)
	out := make([]any, len(estimates))
	for i, e := range estimates {
		out[i] = map[string]any{
			"profile_id":     e.ProfileID,
			"description":    e.Description,
			"seconds":        e.Seconds,
			"human_readable": e.HumanReadable,
		}
	}
	return js.ValueOf(out)
}

// Side-effect: keep a reference to the words package init so TinyGo
// embeds the wordlist. Without this the linker may dead-code-strip it.
var _ = words.EFFLargeWordCount

// Reference json package so the encoded JSON support is linked even if
// no other code path uses it in the wasm-only build (the secretgen
// callers already use it, but explicit is safer).
var _ = json.Marshal
