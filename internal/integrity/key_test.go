package integrity

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestKeyFileIsOwnerOnly pins the one custody property the process can enforce:
// a seed this tool creates is readable by its owner and nobody else.
func TestKeyFileIsOwnerOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("windows file modes do not carry POSIX permission bits")
	}
	path := filepath.Join(t.TempDir(), KeyFileName)
	key, err := LoadOrCreateKey(path)
	if err != nil {
		t.Fatalf("creating the key: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stating the key: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("a new seed must be 0600, got %04o", perm)
	}
	again, err := LoadOrCreateKey(path)
	if err != nil {
		t.Fatalf("loading the existing key: %v", err)
	}
	if again.KeyID != key.KeyID || KeyIDOf(again.Public) != key.KeyID {
		t.Fatalf("loading an existing seed changed its identity: %s vs %s", again.KeyID, key.KeyID)
	}
}

// TestLoadKeyDoesNotCreate is the difference between describing a key and minting
// one: the read-only loader leaves an absent path absent.
func TestLoadKeyDoesNotCreate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.ed25519")
	if _, err := LoadKey(path); err == nil {
		t.Fatalf("LoadKey accepted a path that does not exist")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("LoadKey created the file it was asked to read: %v", err)
	}
}
