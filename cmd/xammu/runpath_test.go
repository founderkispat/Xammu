package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunPathRejectsAnythingButOneDirectoryName(t *testing.T) {
	root := t.TempDir()
	bad := []string{
		"", ".", "..", "../x", "..\\x", "a/b", "a\\b", "/x", "\\x",
		"C:\\x", "C:/x", `C:x`, "a\x00b",
	}
	for _, id := range bad {
		if _, err := runPath(root, id); !errors.Is(err, errUsage) {
			t.Errorf("run id %q must be refused as a usage error, got %v", id, err)
		}
	}
	for _, id := range []string{"run-1", "r_1", "a..b", ".hidden", "run.1"} {
		got, err := runPath(root, id)
		if err != nil {
			t.Errorf("run id %q must be accepted: %v", id, err)
			continue
		}
		if want := filepath.Join(root, id); got != want {
			t.Errorf("run id %q resolved to %q, want %q", id, got, want)
		}
	}
	if _, err := runPath("", "run-1"); !errors.Is(err, errUsage) {
		t.Fatalf("an empty runs directory must be refused, got %v", err)
	}
}

func TestEveryLookupUsesTheSameContainment(t *testing.T) {
	root := t.TempDir()
	if _, err := bundleDir("", "../escape", root); !errors.Is(err, errUsage) {
		t.Fatalf("bundleDir must refuse a traversal id, got %v", err)
	}
	p := planFlags{runsDir: root, runID: "../escape"}
	if _, err := p.bundle(); !errors.Is(err, errUsage) {
		t.Fatalf("planFlags.bundle must refuse a traversal id, got %v", err)
	}
	if _, err := runPath(root, ".."); !errors.Is(err, errUsage) {
		t.Fatalf("runPath must refuse .., got %v", err)
	}
}

func TestRunRefusesATraversalIDBeforeSending(t *testing.T) {
	canary := newCanary(t)
	dir := t.TempDir()
	auth := testAuth(t, canary.port())
	authPath := writeAuthFile(t, dir, auth, "auth.json")
	runsDir := filepath.Join(dir, "runs")

	code, out, errs := run(t, "run", "--authorization", authPath, "--authorize", auth.Ref,
		"--issuer-keyring", testKeyring(dir),
		"--run", "../escape", "--corpus", testCorpusRoot, "--runs-dir", runsDir,
		"--class", "sqli", "--vector", "query", "--budget", "24",
		"--signing-key", filepath.Join(dir, "outside.ed25519"))
	if code != 2 {
		t.Fatalf("a traversal run id must exit 2, got %d\nstdout: %s\nstderr: %s", code, out, errs)
	}
	if !strings.Contains(errs, "is not a run id") {
		t.Fatalf("the refusal must name the identifier problem:\n%s", errs)
	}
	canary.idle(t, "run")
	if _, err := os.Stat(filepath.Join(dir, "escape")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a refused run must not create the escaped directory: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "runs")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a refused run must not create the runs directory: %v", err)
	}
}
