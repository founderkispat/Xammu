package report

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"xammu/internal/contracts"
)

// gitTimeout bounds the optional Git lookups. A run does not depend on Git, and
// a repository large enough to make status slow must not make the report slow:
// past the timeout the identity falls back to the content digest.
const gitTimeout = 5 * time.Second

// CorpusIdentity names the corpus bytes a run's probes came from.
//
// Digest always describes the bytes on disk. Tree is the Git tree object of the
// corpus subtree when Git can prove those bytes are committed; Dirty says the
// working tree differs from that commit. The identity never comes from HEAD
// alone: an unrelated commit must not rename a corpus that did not change, and
// an uncommitted edit must not hide behind a commit that does not contain it.
type CorpusIdentity struct {
	Digest string
	Tree   string
	Dirty  bool
}

// Ref is the single string a report publishes. A clean tree names the commit
// tree and the digest together; a dirty tree publishes the digest as the
// identity and marks the tree it diverges from; without Git the digest stands
// alone and the report says no commit could be verified.
func (c CorpusIdentity) Ref() string {
	switch {
	case c.Tree == "":
		return c.Digest
	case c.Dirty:
		return c.Digest + " git:" + c.Tree + "+dirty"
	default:
		return "git:" + c.Tree + " " + c.Digest
	}
}

// CorpusCommitRef names the exact corpus bytes a run's probes came from and,
// when Git is available, the commit tree that contains them. The value is
// derived from the content, so re-reading the same bytes yields the same ref
// regardless of later commits.
func CorpusCommitRef(root string) (string, error) {
	id, err := CorpusIdentityOf(root)
	if err != nil {
		return "", err
	}
	return id.Ref(), nil
}

// CorpusIdentityOf computes the content digest and, when possible, the Git
// context. Git is an optional runtime dependency: a missing binary, a directory
// outside a repository, a repository with no commit or a timeout all leave Tree
// empty instead of failing the report.
func CorpusIdentityOf(root string) (CorpusIdentity, error) {
	digest, err := corpusContentDigest(root)
	if err != nil {
		return CorpusIdentity{}, err
	}
	id := CorpusIdentity{Digest: digest}

	absRoot, err := filepath.Abs(root)
	if err != nil {
		return id, nil
	}
	top, ok := gitOutput(absRoot, "rev-parse", "--show-toplevel")
	if !ok {
		return id, nil
	}
	repo := strings.TrimSpace(top)
	if repo == "" {
		return id, nil
	}
	rel, err := filepath.Rel(repo, absRoot)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return id, nil
	}
	spec := "HEAD^{tree}"
	relPath := "."
	if rel != "." {
		relPath = filepath.ToSlash(rel)
		spec = "HEAD:" + relPath
	}
	tree, ok := gitOutput(repo, "rev-parse", "--verify", spec)
	if !ok {
		return id, nil
	}
	tree = strings.TrimSpace(tree)
	if !isObjectID(tree) {
		return id, nil
	}
	status, ok := gitOutput(repo, "status", "--porcelain", "--", relPath)
	if !ok {
		return id, nil
	}
	id.Tree = tree
	id.Dirty = strings.TrimSpace(status) != ""
	return id, nil
}

// corpusContentDigest hashes every corpus file by relative path and content. It
// is the identity that does not depend on Git at all.
func corpusContentDigest(root string) (string, error) {
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

// gitOutput runs one read-only Git query with a timeout and no shell. Optional
// locks are disabled so inspecting the corpus never refreshes or writes the
// repository's index.
func gitOutput(dir string, args ...string) (string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), gitTimeout)
	defer cancel()
	full := append([]string{"--no-optional-locks", "-C", dir}, args...)
	cmd := exec.CommandContext(ctx, "git", full...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_OPTIONAL_LOCKS=0")
	out, err := cmd.Output()
	if err != nil {
		return "", false
	}
	return string(out), true
}

func isObjectID(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
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
