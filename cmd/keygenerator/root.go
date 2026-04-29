package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/rafaelperoco/keygenerator/internal/charset"
	"github.com/rafaelperoco/keygenerator/internal/generator"
	"github.com/spf13/cobra"
)

// newRootCmd builds the root cobra command. M1 preserves v1 behavior
// exactly (including the v1 --exclude post-filter quirk and the mutually
// exclusive --letters/--special flags) so the refactor is observably a
// no-op. The bugs and flag overhaul land in M2.
func newRootCmd() *cobra.Command {
	var (
		lettersFlag bool
		specialFlag bool
		lengthFlag  int
		excludeFlag string
	)

	cmd := &cobra.Command{
		Use:   "keygenerator",
		Short: "A CLI tool to generate passwords with entropy and complexity",
		Long:  "A CLI tool to generate passwords with entropy and complexity",
		RunE: func(cmd *cobra.Command, args []string) error {
			if lettersFlag && specialFlag {
				return fmt.Errorf("-l (letters) and -s (special) flags cannot be used together")
			}
			id := "alphanum-v1"
			if specialFlag {
				id = "alphanum-symbols-v1"
			}
			cs, err := charset.Get(id)
			if err != nil {
				return err
			}
			pw, err := generator.Generate(generator.Request{
				Charset: cs,
				Length:  lengthFlag,
			})
			if err != nil {
				return err
			}
			if excludeFlag != "" {
				pw = excludeRunes(pw, excludeFlag)
			}
			fmt.Fprintln(os.Stdout, pw)
			return nil
		},
	}

	cmd.Flags().BoolVarP(&lettersFlag, "letters", "l", false, "use letters and numbers")
	cmd.Flags().BoolVarP(&specialFlag, "special", "s", false, "use letters, numbers and special characters")
	cmd.Flags().IntVarP(&lengthFlag, "length", "n", 20, "length of the password")
	cmd.Flags().StringVarP(&excludeFlag, "exclude", "e", "", "exclude characters from the password")

	return cmd
}

// excludeRunes is the v1 post-generation filter, preserved verbatim for M1
// behavior parity. Replaced by charset.Exclude in M2.
func excludeRunes(s, drop string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if !strings.ContainsRune(drop, r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}
