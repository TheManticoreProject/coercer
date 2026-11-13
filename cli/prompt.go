package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/TheManticoreProject/Manticore/logger"
	"golang.org/x/term"
)

// ResolvePassword fills in the password by asking for it when no secret was supplied.
//
// Parameters:
//
//	authDomain (string): The domain of the identity, shown in the prompt, may be empty.
//	authUsername (string): The user the password is for, shown in the prompt.
//	authPassword (*string): The password flag, written to when the prompt is used.
//	authNoPass (bool): When true, no prompt happens and no password is set.
//	otherSecrets (...string): Any other secret the tool accepts, such as NT hashes, an
//	  AES key or the path to a ticket. A non-empty one suppresses the prompt.
//
// Returns:
//
//	An error if the password could not be read, or if the caller supplied an empty one,
//	nil otherwise.
func ResolvePassword(authDomain string, authUsername string, authPassword *string, authNoPass bool, otherSecrets ...string) error {
	if *authPassword != "" {
		return nil
	}
	for _, secret := range otherSecrets {
		if secret != "" {
			return nil
		}
	}

	if authNoPass {
		return nil
	}

	password, err := PromptForPassword(authDomain, authUsername)
	if err != nil {
		return err
	}
	if password == "" {
		return fmt.Errorf("no password provided, pass --no-pass to bind without one")
	}

	*authPassword = password
	return nil
}

// PromptForPassword asks for a password on the terminal.
//
// Parameters:
//
//	authDomain (string): The domain of the identity the password is for, may be empty.
//	authUsername (string): The user the password is for.
//
// Returns:
//
//	The password, or an error if it could not be read.
func PromptForPassword(authDomain string, authUsername string) (string, error) {
	identity := authUsername
	if authDomain != "" {
		identity = fmt.Sprintf("%s\\%s", authDomain, authUsername)
	}

	fmt.Fprintf(os.Stderr, "  | Password for '%s': ", identity)

	if term.IsTerminal(int(os.Stdin.Fd())) {
		password, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", fmt.Errorf("error reading the password: %w", err)
		}
		return string(password), nil
	}

	fmt.Fprintln(os.Stderr)
	logger.Debug("The input is not a terminal, reading the password from stdin without hiding it")

	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return "", fmt.Errorf("error reading the password: %w", err)
		}
		return "", fmt.Errorf("no password on stdin")
	}

	return strings.TrimRight(scanner.Text(), "\r\n"), nil
}
