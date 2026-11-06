package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"xammu/internal/integrity"
)

// cmdKey is the read-only side of key custody. It loads an existing seed with
// LoadKey, never LoadOrCreateKey, so asking about a key cannot mint one, and it
// publishes only what a verifier needs to identify the signer: the public key,
// the key id the manifest records and the full fingerprint the authorizations
// quote. The seed itself never leaves the file.
func cmdKey(c *cli, args []string) error {
	if len(args) == 0 || args[0] != "inspect" {
		return fmt.Errorf("%w: key takes the subcommand inspect", errUsage)
	}
	fs := newFlagSet("key inspect", c.err)
	var keyPath string
	fs.StringVar(&keyPath, "key", "", "ed25519 seed file to describe; it must already exist")
	if err := parseFlags(fs, args[1:]); err != nil {
		return err
	}
	if err := requireNoStrayArgs(fs); err != nil {
		return err
	}
	if keyPath == "" {
		return fmt.Errorf("%w: key inspect needs --key FILE", errUsage)
	}
	key, err := integrity.LoadKey(keyPath)
	if err != nil {
		// A path that is not a seed is an invocation problem: the operator pointed
		// at the wrong file, and nothing was signed or created.
		return fmt.Errorf("%w: %v", errUsage, err)
	}
	fmt.Fprintf(c.out, "key %s (read only; nothing was created)\n", filepath.ToSlash(keyPath))
	fmt.Fprintf(c.out, "  algorithm    ed25519\n")
	fmt.Fprintf(c.out, "  key id       %s\n", key.KeyID)
	fmt.Fprintf(c.out, "  public key   %s\n", hex.EncodeToString(key.Public))
	fmt.Fprintf(c.out, "  fingerprint  %s\n", integrity.KeyFingerprint(key.Public))
	if note := keyFileNote(keyPath); note != "" {
		fmt.Fprintf(c.out, "  file mode    %s\n", note)
	}
	fmt.Fprint(c.out, "  seed         not printed; it stays in the file named above\n")
	return nil
}

// keyFileNote reports the permission bits an operator can act on. Windows file
// modes do not carry group/world bits, so the platform check keeps the command
// from claiming a custody property it cannot see.
func keyFileNote(path string) string {
	if runtime.GOOS == "windows" {
		return ""
	}
	info, err := os.Stat(path)
	if err != nil {
		return "unreadable after load; check custody before signing"
	}
	perm := info.Mode().Perm()
	if perm&0o077 != 0 {
		return fmt.Sprintf("%04o (group/world readable; chmod 600 before signing)", perm)
	}
	return fmt.Sprintf("%04o (owner-only)", perm)
}
