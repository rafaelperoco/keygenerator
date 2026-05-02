// Command secretgenerator is a CLI for generating auditable random passwords.
package main

import (
	"errors"
	"fmt"
	"os"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		var ce *codedError
		if errors.As(err, &ce) {
			os.Exit(ce.code)
		}
		os.Exit(ExitInvalidArgs)
	}
}
