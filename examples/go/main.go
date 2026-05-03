// Generate an auditable password directly from Go using the public
// pkg/secretgen API — no subprocess, no JSON parsing.
//
// This is the recommended path for Go callers because it returns
// typed structs and matches the CLI's schema-v1 contract 1:1.
//
// Run from the repo root:
//
//	go run ./examples/go
package main

import (
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/rafaelperoco/secretgenerator/pkg/secretgen"
)

func main() {
	res, err := secretgen.Password(secretgen.PasswordOptions{
		Length:          24,
		CharsetID:       "alphanum-symbols-v1",
		RequiredClasses: "lower,upper,digit,symbol",
	})
	if err != nil {
		if errors.Is(err, secretgen.ErrBelowEntropyFloor) {
			log.Fatalf("policy floor rejected the request: %v", err)
		}
		log.Fatal(err)
	}

	// In real code, hand res.Password to whatever consumes it (HTTP
	// response, env var, secret manager) and never log it. We write to
	// stdout directly here because this is a demo.
	_, _ = os.Stdout.WriteString("password: " + res.Password + "\n")
	fmt.Printf("entropy:  %.1f bits\n", res.EntropyBits)

	for _, e := range secretgen.EstimateCrackTime(res.EntropyBits) {
		if e.ProfileID == "nation-state-v1" {
			fmt.Printf("crack:    %s (nation-state)\n", e.HumanReadable)
			break
		}
	}
}
