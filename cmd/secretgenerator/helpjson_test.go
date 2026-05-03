package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// helpDoc is a relaxed mirror of helpJSON used for assertions; we don't
// want to import the unexported type into a black-box style test, but
// since this is a white-box test in the same package we can use it
// directly.
//
// We exercise emitHelpJSON via newRootCmd() to catch flag-registration
// mistakes that would slip through a unit test of buildHelpJSON alone.

func TestEmitHelpJSON_RootContainsAllSubcommands(t *testing.T) {
	cmd := newRootCmd()
	var buf bytes.Buffer
	if err := emitHelpJSON(&buf, cmd); err != nil {
		t.Fatalf("emitHelpJSON: %v", err)
	}
	var doc helpJSON
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("decode: %v\n%s", err, buf.String())
	}
	if doc.HelpJSONSchemaVersion != helpJSONSchemaVersion {
		t.Errorf("schema version = %d", doc.HelpJSONSchemaVersion)
	}
	if doc.Name != "secretgenerator" {
		t.Errorf("name = %q", doc.Name)
	}

	want := []string{"api-key", "entropy", "passphrase", "password", "pin", "secret"}
	got := make([]string, 0, len(doc.Subcommands))
	for _, s := range doc.Subcommands {
		got = append(got, s.Name)
	}
	for _, w := range want {
		found := false
		for _, g := range got {
			if g == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing subcommand %q in %v", w, got)
		}
	}
}

func TestEmitHelpJSON_FlagTypesAreNative(t *testing.T) {
	cmd := newRootCmd()
	var buf bytes.Buffer
	if err := emitHelpJSON(&buf, cmd); err != nil {
		t.Fatalf("emitHelpJSON: %v", err)
	}
	var doc helpJSON
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// Find the password subcommand.
	var passwordDoc helpJSON
	for _, s := range doc.Subcommands {
		if s.Name == "password" {
			passwordDoc = s
		}
	}
	if passwordDoc.Name == "" {
		t.Fatal("password subcommand missing")
	}

	want := map[string]struct {
		typ     string
		hasDef  bool
		defKind string // "bool", "int", "float", "string"
	}{
		"length":           {"integer", true, "int"},
		"charset":          {"string", true, "string"},
		"json":             {"boolean", true, "bool"},
		"min-entropy-bits": {"number", true, "float"},
		"allow-weak":       {"boolean", true, "bool"},
	}

	for _, f := range passwordDoc.Flags {
		exp, ok := want[f.Name]
		if !ok {
			continue
		}
		if f.Type != exp.typ {
			t.Errorf("flag %q type = %q, want %q", f.Name, f.Type, exp.typ)
		}
		if exp.hasDef && f.Default == nil {
			t.Errorf("flag %q expected default, got nil", f.Name)
		}
		// Spot-check that default is the native Go type, not stringified.
		if exp.defKind == "bool" {
			if _, ok := f.Default.(bool); !ok {
				t.Errorf("flag %q default = %v (%T), want bool", f.Name, f.Default, f.Default)
			}
		}
		if exp.defKind == "int" {
			// JSON numbers decode as float64 in Go's encoding/json; the
			// raw bytes themselves are integer. We assert that the
			// default unmarshals as a numeric type rather than a string.
			switch f.Default.(type) {
			case float64, int, int64, json.Number:
				// ok
			default:
				t.Errorf("flag %q default = %v (%T), want numeric", f.Name, f.Default, f.Default)
			}
		}
	}
}

func TestEmitHelpJSON_HelpFlagOmitted(t *testing.T) {
	cmd := newRootCmd()
	var buf bytes.Buffer
	if err := emitHelpJSON(&buf, cmd); err != nil {
		t.Fatalf("emitHelpJSON: %v", err)
	}
	if strings.Contains(buf.String(), `"name": "help"`) {
		t.Errorf("help flag should be omitted from help-json output")
	}
}

func TestEmitHelpJSON_GlobalFlagsListed(t *testing.T) {
	cmd := newRootCmd()
	var buf bytes.Buffer
	if err := emitHelpJSON(&buf, cmd); err != nil {
		t.Fatalf("emitHelpJSON: %v", err)
	}
	var doc helpJSON
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Each subcommand should list --help-json under global_flags (it's
	// persistent on root) so an agent introspecting that subcommand
	// directly knows the flag exists.
	for _, sub := range doc.Subcommands {
		found := false
		for _, gf := range sub.GlobalFlags {
			if gf.Name == "help-json" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("subcommand %q missing help-json in global_flags", sub.Name)
		}
	}
}

func TestEmitHelpJSON_NoCobraInternalCommands(t *testing.T) {
	cmd := newRootCmd()
	var buf bytes.Buffer
	if err := emitHelpJSON(&buf, cmd); err != nil {
		t.Fatal(err)
	}
	var doc helpJSON
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	for _, sub := range doc.Subcommands {
		if sub.Name == "help" || sub.Name == "completion" {
			t.Errorf("subcommand %q should be filtered from help-json", sub.Name)
		}
	}
}
