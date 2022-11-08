// Language: go
// A CLI tool to generate passwords with entropy and complexity
// generate passwords just with letters and numbers or with special characters (Default)
// use cobra for CLI

package main

import (
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/spf13/cobra"
)

var (
	// letters and numbers
	letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	// letters, numbers and special characters
	lettersAndSpecial = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+{}|:<>?`~-=[]\\;',./")

	// flags
	lettersFlag bool
	specialFlag bool
	lengthFlag  int
)

func main() {
	// root command
	var rootCmd = &cobra.Command{
		Use:   "passgen",
		Short: "A CLI tool to generate passwords with entropy and complexity",
		Long:  `A CLI tool to generate passwords with entropy and complexity`,
		Run: func(cmd *cobra.Command, args []string) {
			// generate password
			password := generatePassword()
			// print password
			fmt.Println(password)
		},
	}

	// flags
	rootCmd.Flags().BoolVarP(&lettersFlag, "letters", "l", false, "use letters and numbers")
	rootCmd.Flags().BoolVarP(&specialFlag, "special", "s", false, "use letters, numbers and special characters")
	rootCmd.Flags().IntVarP(&lengthFlag, "length", "n", 20, "length of the password")

	// execute command
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

// generatePassword generates a password with entropy and complexity
func generatePassword() string {
	// seed random
	rand.Seed(time.Now().UnixNano())

	// check flags
	if lettersFlag {
		// generate password with letters and numbers
		return generatePasswordWithLetters()
	} else if specialFlag {
		// generate password with letters, numbers and special characters
		return generatePasswordWithLettersAndSpecial()
	} else {
		// generate password with letters, numbers and special characters
		return generatePasswordWithLettersAndSpecial()
	}
}

// generatePasswordWithLetters generates a password with letters and numbers
func generatePasswordWithLetters() string {
	// password
	password := make([]rune, lengthFlag)

	// generate password
	for i := range password {
		password[i] = letters[rand.Intn(len(letters))]
	}

	// return password
	return string(password)
}

// generatePasswordWithLettersAndSpecial generates a password with letters, numbers and special characters
func generatePasswordWithLettersAndSpecial() string {
	// password
	password := make([]rune, lengthFlag)

	// generate password
	for i := range password {
		password[i] = lettersAndSpecial[rand.Intn(len(lettersAndSpecial))]
	}

	// return password
	return string(password)
}

// use: go run main.go -h