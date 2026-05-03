package main

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// helpJSONSchemaVersion mirrors audit.SchemaVersion for the meta-schema
// describing this output. Bumped independently of the credential schema —
// the help-json shape is its own contract.
const helpJSONSchemaVersion = 1

// HelpJSONCmd is the cobra command name surfaced to agents asking "what is
// this CLI". The output is JSON describing the command tree, all flags,
// their types, defaults, and prose. Agents prefer this to parsing the
// human-readable --help.
//
// The shape is intentionally similar to OpenAPI parameter blocks so any
// agent already familiar with OpenAPI can introspect without learning a
// new schema.
type helpJSON struct {
	HelpJSONSchemaVersion int           `json:"help_json_schema_version,omitempty"`
	Name                  string        `json:"name"`
	Use                   string        `json:"use"`
	Short                 string        `json:"short,omitempty"`
	Long                  string        `json:"long,omitempty"`
	Example               string        `json:"example,omitempty"`
	Aliases               []string      `json:"aliases,omitempty"`
	Subcommands           []helpJSON    `json:"subcommands,omitempty"`
	Flags                 []helpFlagDoc `json:"flags,omitempty"`
	GlobalFlags           []helpFlagDoc `json:"global_flags,omitempty"`
}

type helpFlagDoc struct {
	Name        string `json:"name"`
	Shorthand   string `json:"shorthand,omitempty"`
	Type        string `json:"type"`
	Default     any    `json:"default,omitempty"`
	Description string `json:"description"`
	Hidden      bool   `json:"hidden,omitempty"`
}

// emitHelpJSON serializes the command tree (cmd and its subcommands) into
// JSON and writes it to w. The recurse flag controls whether subcommands
// are inlined; the CLI's --help-json includes the full tree.
func emitHelpJSON(w io.Writer, cmd *cobra.Command) error {
	doc := buildHelpJSON(cmd, true)
	doc.HelpJSONSchemaVersion = helpJSONSchemaVersion
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func buildHelpJSON(cmd *cobra.Command, recurse bool) helpJSON {
	doc := helpJSON{
		Name:    cmd.Name(),
		Use:     cmd.UseLine(),
		Short:   cmd.Short,
		Long:    strings.TrimSpace(cmd.Long),
		Example: strings.TrimSpace(cmd.Example),
		Aliases: cmd.Aliases,
		Flags:   collectFlags(cmd.LocalFlags()),
	}

	// Inherited / persistent flags (e.g. --help-json itself, --json on
	// every subcommand) are listed separately so agents can tell which
	// flags are global vs subcommand-local.
	doc.GlobalFlags = collectFlags(cmd.InheritedFlags())

	if recurse {
		var subs []helpJSON
		for _, c := range cmd.Commands() {
			if c.Hidden || c.Name() == "help" || c.Name() == "completion" {
				continue
			}
			subs = append(subs, buildHelpJSON(c, true))
		}
		sort.Slice(subs, func(i, j int) bool { return subs[i].Name < subs[j].Name })
		doc.Subcommands = subs
	}
	return doc
}

func collectFlags(set *pflag.FlagSet) []helpFlagDoc {
	var out []helpFlagDoc
	set.VisitAll(func(f *pflag.Flag) {
		if f.Name == "help" {
			return // cobra builtin, don't emit
		}
		out = append(out, helpFlagDoc{
			Name:        f.Name,
			Shorthand:   f.Shorthand,
			Type:        flagType(f),
			Default:     flagDefault(f),
			Description: strings.TrimSpace(f.Usage),
			Hidden:      f.Hidden,
		})
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// flagType maps pflag's type strings to the OpenAPI-ish names agents
// expect. Anything unknown falls through as the original string so we
// never lie about the type.
func flagType(f *pflag.Flag) string {
	switch f.Value.Type() {
	case "int", "int64", "int32", "uint", "uint64":
		return "integer"
	case "float64", "float32":
		return "number"
	case "bool":
		return "boolean"
	case "string", "stringSlice", "stringArray":
		if f.Value.Type() != "string" {
			return "array<string>"
		}
		return "string"
	case "duration":
		return "duration"
	}
	return f.Value.Type()
}

// flagDefault returns the default value of a flag in its native Go type
// when possible, falling back to the string form. Booleans and numbers
// must be returned as JSON booleans/numbers (not strings) for agents
// that do strict type checking.
func flagDefault(f *pflag.Flag) any {
	switch f.Value.Type() {
	case "bool":
		return f.DefValue == "true"
	case "int", "int64", "int32", "uint", "uint64":
		var i int64
		_, err := fmt.Sscanf(f.DefValue, "%d", &i)
		if err == nil {
			return i
		}
	case "float64", "float32":
		var v float64
		_, err := fmt.Sscanf(f.DefValue, "%g", &v)
		if err == nil {
			return v
		}
	}
	if f.DefValue == "" {
		return nil
	}
	return f.DefValue
}
