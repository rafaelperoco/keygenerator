package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var (
	letters           = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	lettersAndSpecial = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+{}|:<>?`~-=[]\\;',./")
	lettersFlag       bool
	specialFlag       bool
	lengthFlag        int
	excludeFlag       string
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "pwdgen",
		Short: "A CLI tool to generate passwords with entropy and complexity",
		Long:  `A CLI tool to generate passwords with entropy and complexity`,
		Run: func(cmd *cobra.Command, args []string) {
			if lettersFlag && specialFlag {
				fmt.Println("Error: -l (letters) and -s (special) flags cannot be used together.")
				os.Exit(1)
			}

			password := generatePassword(lengthFlag)
			if excludeFlag != "" {
				fmt.Println(excludeCharacters(password))
			} else {
				fmt.Println(password)
			}
		},
	}
	rootCmd.Flags().BoolVarP(&lettersFlag, "letters", "l", false, "use letters and numbers")
	rootCmd.Flags().BoolVarP(&specialFlag, "special", "s", false, "use letters, numbers and special characters")
	rootCmd.Flags().IntVarP(&lengthFlag, "length", "n", 20, "length of the password")
	rootCmd.Flags().StringVarP(&excludeFlag, "exclude", "e", "", "exclude characters from the password")

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func generatePassword(length int) string {
	var characters []rune
	if specialFlag {
		characters = lettersAndSpecial
	} else {
		characters = letters
	}

	var password strings.Builder
	password.Grow(length)

	for i := 0; i < length; i++ {
		char, err := rand.Int(rand.Reader, big.NewInt(int64(len(characters))))
		if err != nil {
			fmt.Println("Error generating random character:", err)
			continue
		}
		password.WriteRune(characters[char.Int64()])
	}

	return password.String()
}

func excludeCharacters(password string) string {
	var newPassword strings.Builder
	newPassword.Grow(len(password))

	for _, char := range password {
		if !containsRune(excludeFlag, char) {
			newPassword.WriteRune(char)
		}
	}

	return newPassword.String()
}

func containsRune(s string, r rune) bool {
	for _, a := range s {
		if a == r {
			return true
		}
	}
	return false
}
