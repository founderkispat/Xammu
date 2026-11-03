package report

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"xammu/internal/contracts"
)

// CorpusCommitRef names the exact corpus bytes a run's probes came from. The
// repository commit is preferred when one exists, because a reviewer can check out a
// commit; without a git directory the digest of every corpus file is used, which names
// the same content by its hash instead. Either way the report's evidence section points
// at a corpus that can be re-read rather than at "the one that was there".
func CorpusCommitRef(root string) (string, error) {
	if ref, ok := gitCommitRef(root); ok {
		return ref, nil
	}
	var lines []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".jsonl") {
			return nil
		}
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			return fmt.Errorf("report: cannot hash corpus file %s: %w", path, readErr)
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		sum := sha256.Sum256(raw)
		lines = append(lines, filepath.ToSlash(rel)+"\x00"+hex.EncodeToString(sum[:]))
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("report: cannot inventory the corpus at %s: %w", root, err)
	}
	if len(lines) == 0 {
		return "", fmt.Errorf("report: the corpus at %s holds no .jsonl files, so it has no identity to "+
			"publish: a report whose corpus cannot be named cannot be reproduced", root)
	}
	sort.Strings(lines)
	return "corpus-digest:" + strings.TrimPrefix(
		contracts.NewDigest([]byte(strings.Join(lines, "\n"))), "sha256:"), nil
}

// gitCommitRef reads the commit of the repository the corpus lives in, falling back to
// the working-tree digest when there is no git directory or no commit yet.
func gitCommitRef(root string) (string, bool) {
	dir := root
	for {
		head := filepath.Join(dir, ".git", "HEAD")
		raw, err := os.ReadFile(head)
		if err == nil {
			ref := strings.TrimSpace(string(raw))
			if strings.HasPrefix(ref, "ref: ") {
				path := filepath.Join(dir, ".git", filepath.FromSlash(strings.TrimPrefix(ref, "ref: ")))
				if commit, err := os.ReadFile(path); err == nil {
					return "git:" + strings.TrimSpace(string(commit)), true
				}
				return "", false
			}
			if ref != "" {
				return "git:" + ref, true
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false
		}
		dir = parent
	}
}

// ManifestDigestOf hashes the manifest file as it stands on disk. The report publishes
// the digest of the artifact a reader will actually open, not of the payload the tool
// remembers writing: if the file changed afterwards, the report says so.
func ManifestDigestOf(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("report: cannot hash the manifest at %s: %w", path, err)
	}
	return contracts.NewDigest(raw), nil
}
