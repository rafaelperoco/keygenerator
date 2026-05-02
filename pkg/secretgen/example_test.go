package secretgen_test

import (
	"errors"
	"fmt"

	"github.com/rafaelperoco/secretgenerator/pkg/secretgen"
)

func ExamplePassword() {
	res, err := secretgen.Password(secretgen.PasswordOptions{
		Length:          24,
		CharsetID:       "alphanum-symbols-v1",
		RequiredClasses: "lower,upper,digit,symbol",
	})
	if err != nil {
		panic(err)
	}
	_ = res.Password // generated credential
	fmt.Println("entropy bits:", int(res.EntropyBits))
	// Output:
	// entropy bits: 156
}

func ExampleSecret() {
	res, err := secretgen.Secret(secretgen.SecretOptions{Bytes: 32})
	if err != nil {
		panic(err)
	}
	fmt.Println("length:", res.Length, "entropy:", int(res.EntropyBits))
	// Output:
	// length: 43 entropy: 256
}

func ExamplePassphrase() {
	res, err := secretgen.Passphrase(secretgen.PassphraseOptions{Words: 8})
	if err != nil {
		panic(err)
	}
	fmt.Println("words:", res.Length, "entropy:", int(res.EntropyBits))
	// Output:
	// words: 8 entropy: 103
}

func ExampleAPIKey() {
	res, err := secretgen.APIKey(secretgen.APIKeyOptions{
		Prefix:    "sk_live",
		Separator: "_",
		Length:    32,
	})
	if err != nil {
		panic(err)
	}
	fmt.Println("subcommand:", res.Subcommand, "entropy:", int(res.EntropyBits))
	// Output:
	// subcommand: api-key entropy: 190
}

func Example_errorHandling() {
	// Asking for a 4-character password is below the default 80-bit floor.
	_, err := secretgen.Password(secretgen.PasswordOptions{Length: 4})
	fmt.Println("entropy floor hit:", errors.Is(err, secretgen.ErrBelowEntropyFloor))
	// Output:
	// entropy floor hit: true
}

func ExampleEstimateCrackTime() {
	// 128 bits is the NIST SP 800-131A 2030 target for symmetric keys.
	estimates := secretgen.EstimateCrackTime(128)
	fmt.Println("number of profiles:", len(estimates))
	for _, e := range estimates {
		_ = e.HumanReadable // e.g. "1.4e+20 times the age of the universe"
	}
	// Output:
	// number of profiles: 5
}
