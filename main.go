package main

import (
	"fmt"
	"math/rand"
	"os"
	"time"

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
	rand.Seed(time.Now().UnixNano())

	var password []rune
	if lettersFlag {
		password = make([]rune, lengthFlag)
		for i := range password {
			password[i] = letters[rand.Intn(len(letters))]
		}
	} else if specialFlag {
		password = make([]rune, lengthFlag)
		for i := range password {
			password[i] = lettersAndSpecial[rand.Intn(len(lettersAndSpecial))]
		}
	} else {
		password = make([]rune, lengthFlag)
		for i := range password {
			password[i] = lettersAndSpecial[rand.Intn(len(lettersAndSpecial))]
		}
	}
	return string(password)
}

func excludeCharacters(password string) string {
	var result string
	for _, c := range password {
		if !contains(excludeFlag, c) {
			result += string(c)
		}
	}
	return result
}

func contains(s string, c rune) bool {
	for _, r := range s {
		if r == c {
			return true
		}
	}
	return false
}