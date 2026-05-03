// Command secretgenerator is a CLI for generating auditable random passwords.
package main

import (
	"errors"
	"fmt"
	"os"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		var ce *codedError
		if errors.As(err, &ce) {
			// When the subcommand already emitted a structured JSON
			// error envelope on stdout, do not duplicate the message on
			// stderr — the agent has the structured form already.
			if !ce.jsonEmitted {
				fmt.Fprintln(os.Stderr, err)
			}
			os.Exit(ce.code)
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(ExitInvalidArgs)
	}
}
