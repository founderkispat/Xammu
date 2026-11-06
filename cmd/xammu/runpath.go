package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// runPath resolves a --run id under --runs-dir and refuses anything that is not
// a single path component. A run id is published in findings and copied into
// reproduction commands, so a bundle that names one must not be able to steer a
// reader's command outside the runs directory. --store remains the deliberate
// way to name an arbitrary directory.
//
// The containment check is lexical: symlinks created inside runs/ are outside
// this promise. It stops a copied command from writing or reading elsewhere by
// accident; it is not a filesystem sandbox.
func runPath(runsDir, runID string) (string, error) {
	if runsDir == "" {
		return "", fmt.Errorf("%w: --runs-dir is empty, so run %q has no home", errUsage, runID)
	}
	if runID == "" {
		return "", fmt.Errorf("%w: a bundle is named by --run ID or by --store DIR", errUsage)
	}
	if runID == "." || runID == ".." || filepath.Base(runID) != runID ||
		filepath.IsAbs(runID) || filepath.VolumeName(runID) != "" ||
		strings.ContainsAny(runID, `/\:`) || strings.ContainsRune(runID, 0) {
		return "", fmt.Errorf("%w: --run %q is not a run id: a bundle is one directory name under "+
			"--runs-dir, and a path with separators, a volume or a dot segment is refused; "+
			"use --store to name a directory explicitly", errUsage, runID)
	}

	dir := filepath.Join(runsDir, runID)
	absRuns, err := filepath.Abs(runsDir)
	if err != nil {
		return "", fmt.Errorf("%w: cannot resolve --runs-dir %q: %v", errUsage, runsDir, err)
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("%w: cannot resolve the bundle path for %q: %v", errUsage, runID, err)
	}
	rel, err := filepath.Rel(absRuns, absDir)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("%w: --run %q resolves outside --runs-dir %q, so it is refused",
			errUsage, runID, runsDir)
	}
	return dir, nil
}
