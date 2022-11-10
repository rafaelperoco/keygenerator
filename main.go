package main

import (
	"crypto/rand"
	"fmt"
	"os"
	"math/big"

	"github.com/spf13/cobra"
)

var (
	letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	lettersAndSpecial = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+{}|:<>?`~-=[]\\;',./")

	lettersFlag bool
	specialFlag bool
	lengthFlag  int
	excludeFlag string
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "pwdgen",
		Short: "A CLI tool to generate passwords with entropy and complexity",
		Long:  `A CLI tool to generate passwords with entropy and complexity`,
		Run: func(cmd *cobra.Command, args []string) {
			if excludeFlag != "" {
				fmt.Println(excludeCharacters(generatePassword()))
			} else {
				fmt.Println(generatePassword())
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

func generatePassword() string {
	var password string
	var characters []rune

	if lettersFlag && specialFlag {
		characters = lettersAndSpecial
	} else if lettersFlag {
		characters = letters
	} else {
		characters = lettersAndSpecial
	}

	for i := 0; i < lengthFlag; i++ {
		char, _ := rand.Int(rand.Reader, big.NewInt(int64(len(characters))))
		password += string(characters[char.Int64()])
	}

	return password
}

func excludeCharacters(password string) string {
	var newPassword string

	for _, char := range password {
		if !containsRune(excludeFlag, char) {
			newPassword += string(char)
		}
	}

	return newPassword
}

func containsRune(s string, r rune) bool {
	for _, a := range s {
		if a == r {
			return true
		}
	}
	return false
}