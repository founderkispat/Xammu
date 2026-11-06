package report_test

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"xammu/internal/report"
)

func requireGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed; the content digest fallback is tested separately")
	}
}

func gitRun(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-c", "core.autocrlf=false", "-C", dir}, args...)...)
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=xammu test", "GIT_AUTHOR_EMAIL=test@example.invalid",
		"GIT_COMMITTER_NAME=xammu test", "GIT_COMMITTER_EMAIL=test@example.invalid")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func initRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	// t.TempDir is outside the repository on purpose; the ceiling makes the
	// discovery test deterministic even on a host whose temp lives inside one.
	t.Setenv("GIT_CEILING_DIRECTORIES", filepath.Dir(dir))
	gitRun(t, dir, "init", "-q")
	return dir
}

func TestCorpusIdentityNamesTheCommittedTreeNotHead(t *testing.T) {
	requireGit(t)
	repo := initRepo(t)
	corpusDir := filepath.Join(repo, "corpus")
	if err := os.MkdirAll(filepath.Join(corpusDir, "development"), 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(corpusDir, "development", "a.jsonl")
	if err := os.WriteFile(file, []byte(`{"ref":"DEV-A"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, repo, "add", ".")
	gitRun(t, repo, "commit", "-q", "-m", "corpus")

	first, err := report.CorpusIdentityOf(corpusDir)
	if err != nil {
		t.Fatal(err)
	}
	if first.Tree == "" || first.Dirty {
		t.Fatalf("a committed corpus must name a clean tree: %+v", first)
	}
	if !strings.HasPrefix(first.Ref(), "git:"+first.Tree+" corpus-digest:") {
		t.Fatalf("the ref must carry tree and digest: %q", first.Ref())
	}

	// An unrelated commit moves HEAD but not the corpus subtree.
	if err := os.WriteFile(filepath.Join(repo, "README.md"), []byte("notes\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, repo, "add", "README.md")
	gitRun(t, repo, "commit", "-q", "-m", "unrelated")
	second, err := report.CorpusIdentityOf(corpusDir)
	if err != nil {
		t.Fatal(err)
	}
	if second.Tree != first.Tree || second.Ref() != first.Ref() {
		t.Fatalf("an unrelated commit changed the corpus identity: %q -> %q", first.Ref(), second.Ref())
	}

	// An uncommitted corpus edit is not hidden behind the last commit.
	if err := os.WriteFile(file, []byte(`{"ref":"DEV-A-EDITED"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dirty, err := report.CorpusIdentityOf(corpusDir)
	if err != nil {
		t.Fatal(err)
	}
	if !dirty.Dirty || dirty.Tree != first.Tree {
		t.Fatalf("a dirty corpus must keep the tree and say so: %+v", dirty)
	}
	if dirty.Digest == first.Digest {
		t.Fatal("an edited corpus kept its old content digest")
	}
	if !strings.HasSuffix(dirty.Ref(), "git:"+first.Tree+"+dirty") {
		t.Fatalf("the dirty ref must name the diverging tree: %q", dirty.Ref())
	}

	// Committing the edit gives the same bytes a new clean tree.
	gitRun(t, repo, "add", "corpus")
	gitRun(t, repo, "commit", "-q", "-m", "edit corpus")
	committed, err := report.CorpusIdentityOf(corpusDir)
	if err != nil {
		t.Fatal(err)
	}
	if committed.Dirty || committed.Tree == first.Tree {
		t.Fatalf("committing the edit must produce a clean, new tree: %+v", committed)
	}
	if committed.Digest != dirty.Digest {
		t.Fatal("committing the edit changed the content digest")
	}
}

func TestCorpusIdentityFallsBackToTheDigestWithoutGit(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GIT_CEILING_DIRECTORIES", filepath.Dir(dir))
	if err := os.WriteFile(filepath.Join(dir, "a.jsonl"), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	id, err := report.CorpusIdentityOf(dir)
	if err != nil {
		t.Fatal(err)
	}
	if id.Tree != "" || id.Dirty {
		t.Fatalf("a directory outside Git must not invent a commit: %+v", id)
	}
	if id.Ref() != id.Digest || !strings.HasPrefix(id.Ref(), "corpus-digest:") {
		t.Fatalf("the fallback must be the content digest alone: %q", id.Ref())
	}
	ref, err := report.CorpusCommitRef(dir)
	if err != nil || ref != id.Ref() {
		t.Fatalf("CorpusCommitRef must agree with CorpusIdentityOf: %q vs %q (%v)", ref, id.Ref(), err)
	}
}

func TestCorpusIdentityRefusesAnEmptyCorpus(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GIT_CEILING_DIRECTORIES", filepath.Dir(dir))
	if _, err := report.CorpusCommitRef(dir); err == nil {
		t.Fatal("a corpus with no .jsonl files must have no identity")
	}
	if _, err := report.CorpusIdentityOf(dir); err == nil {
		t.Fatal("CorpusIdentityOf must fail the same way")
	}
}

func TestCorpusIdentityDoesNotTouchTheIndex(t *testing.T) {
	requireGit(t)
	repo := initRepo(t)
	corpusDir := filepath.Join(repo, "corpus")
	if err := os.MkdirAll(corpusDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(corpusDir, "a.jsonl"), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, repo, "add", ".")
	gitRun(t, repo, "commit", "-q", "-m", "corpus")
	index := filepath.Join(repo, ".git", "index")
	before, err := os.Stat(index)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := report.CorpusIdentityOf(corpusDir); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(index)
	if err != nil {
		t.Fatal(err)
	}
	if !before.ModTime().Equal(after.ModTime()) || before.Size() != after.Size() {
		t.Fatal("reading the corpus identity rewrote the Git index")
	}
	if _, err := os.Stat(filepath.Join(repo, ".git", "index.lock")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("reading the corpus identity left an index lock behind")
	}
}
