package main

import (
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/spf13/cobra"
)

var (
	size     int
	specials bool
)

func init() {
	size = 16
	specials = false
}

func main() {
	rootCmd := &cobra.Command{
		Use:   "password",
		Short: "Password generator",
		Long:  "A password generator cli with high entropy",
		Run: func(cmd *cobra.Command, args []string) {
			password := generatePassword(size, specials)

			fmt.Println(password)
		},
	}

	rootCmd.Flags().IntVarP(&size, "size", "s", 16, "size of password")
	rootCmd.Flags().BoolVarP(&specials, "specials", "S", false, "add special characters")

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func generatePassword(size int, specials bool) string {
	rand.Seed(time.Now().UnixNano())

	var chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	if specials {
		chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"
	}

	var password string
	for i := 0; i < size; i++ {
		password += string(chars[rand.Intn(len(chars))])
	}

	return password
}