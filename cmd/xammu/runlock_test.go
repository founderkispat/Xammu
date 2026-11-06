package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestBusyLockRefusesTheRunBeforeAnySocket holds the lock for the authorization
// the run is about to spend and then runs the command. The command must exit 2
// with a coordination message, create no bundle and send nothing.
func TestBusyLockRefusesTheRunBeforeAnySocket(t *testing.T) {
	canary := newCanary(t)
	dir := t.TempDir()
	auth := testAuth(t, canary.port())
	authPath := writeAuthFile(t, dir, auth, "auth.json")
	runsDir := filepath.Join(dir, "runs")
	origin, err := originURL(auth.Origins[0])
	if err != nil {
		t.Fatalf("origin: %v", err)
	}

	lock, err := acquireAuthorizationLock(auth.Ref, origin)
	if err != nil {
		t.Fatalf("cannot take the lock the test needs to hold: %v", err)
	}
	defer lock.Release()

	code, out, errs := run(t, "run", "--authorization", authPath, "--authorize", auth.Ref,
		"--issuer-keyring", testKeyring(dir),
		"--run", "busy-lock", "--corpus", testCorpusRoot, "--runs-dir", runsDir,
		"--class", "sqli", "--vector", "query", "--budget", "24",
		"--signing-key", filepath.Join(dir, "outside.ed25519"))
	if code != 2 {
		t.Fatalf("a busy authorization must exit 2, got %d\nstdout: %s\nstderr: %s", code, out, errs)
	}
	if !strings.Contains(errs, "another xammu run is spending authorization") {
		t.Fatalf("the refusal must say why:\n%s", errs)
	}
	canary.idle(t, "run")
	if _, err := os.Stat(filepath.Join(runsDir, "busy-lock")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a refused run must not create a bundle: %v", err)
	}
}

func TestBusyLockIsAUsageError(t *testing.T) {
	lock, err := acquireAuthorizationLock("AUTH-1", "http://127.0.0.1:9")
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	defer lock.Release()
	if _, err := acquireAuthorizationLock("AUTH-1", "http://127.0.0.1:9"); !errors.Is(err, errUsage) {
		t.Fatalf("a busy lock must exit through errUsage, got %v", err)
	}
}
