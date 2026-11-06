package labcheck

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readLab(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "lab", name))
	if err != nil {
		t.Fatalf("reading lab/%s: %v", name, err)
	}
	// The repository stores LF; a Windows checkout under core.autocrlf reads CRLF.
	return strings.ReplaceAll(string(raw), "\r\n", "\n")
}

// TestRepositoryLabIsHardened is the check that keeps the fixture honest: the
// files in the repository must pass the invariants the README claims for them.
func TestRepositoryLabIsHardened(t *testing.T) {
	for _, tc := range []struct {
		name  string
		check func([]byte) []string
		file  string
	}{
		{"compose", CheckCompose, "compose.yaml"},
		{"origin Dockerfile", CheckDockerfile, "origin/Dockerfile"},
		{"waf Dockerfile", CheckDockerfile, "waf/Dockerfile"},
		{"DIGESTS", CheckDigests, "DIGESTS.txt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if findings := tc.check([]byte(readLab(t, tc.file))); len(findings) > 0 {
				t.Fatalf("lab/%s violates its declared invariants:\n  %s",
					tc.file, strings.Join(findings, "\n  "))
			}
		})
	}
}

// TestComposeChecksCatchEachRemovedInvariant mutates one control at a time. A
// checker that only passes the real file would not prove it can fail.
func TestComposeChecksCatchEachRemovedInvariant(t *testing.T) {
	compose := readLab(t, "compose.yaml")
	mutations := []struct {
		name string
		old  string
		new  string
		want string
	}{
		{"internal network", "    internal: true\n", "    internal: false\n", "internal: true"},
		{"read-only root", "  read_only: true\n", "  read_only: false\n", "read_only: true"},
		{"drop ALL capabilities", "    - ALL\n", "    - NET_BIND_SERVICE\n", "cap_drop does not drop ALL"},
		{"no-new-privileges", "    - no-new-privileges:true\n", "", "no-new-privileges:true"},
		{"pids limit", "  pids_limit: 128\n", "", "pids_limit"},
		{"tmpfs", "  tmpfs:\n", "  scratch:\n", "tmpfs"},
		{"log rotation", "      max-size: \"1m\"\n", "", "max-size"},
		{"anchor on one service", "    <<: *lab-defaults\n", "", "service origin: does not include"},
		{"netrunner user", "    user: \"1000:1000\"\n", "", "netrunner: no `user:`"},
		{"published port", "  origin:\n", "  origin:\n    ports:\n      - \"8080:8080\"\n", "ports:"},
		{"privileged", "  origin:\n", "  origin:\n    privileged: true\n", "privileged:"},
		{"host network", "  origin:\n", "  origin:\n    network_mode: host\n", "network_mode:"},
		{"host pid", "  origin:\n", "  origin:\n    pid: host\n", "pid:"},
		{"host volume", "  origin:\n", "  origin:\n    volumes:\n      - /:/host\n", "volumes:"},
		{"control written as a comment", "  read_only: true\n", "  # read_only: true\n", "read_only: true"},
	}
	for _, m := range mutations {
		t.Run(m.name, func(t *testing.T) {
			if !strings.Contains(compose, m.old) {
				t.Fatalf("the fixture no longer contains %q; update this mutation instead of deleting it", m.old)
			}
			mutated := strings.Replace(compose, m.old, m.new, 1)
			findings := CheckCompose([]byte(mutated))
			if len(findings) == 0 {
				t.Fatalf("removing %s was not detected", m.name)
			}
			if !strings.Contains(strings.Join(findings, "\n"), m.want) {
				t.Fatalf("the finding does not mention %q:\n  %s", m.want, strings.Join(findings, "\n  "))
			}
		})
	}
}

func TestDockerfileChecksCatchRemovedInvariants(t *testing.T) {
	origin := readLab(t, "origin/Dockerfile")
	mutations := []struct {
		name string
		old  string
		new  string
		want string
	}{
		{"unpinned base", "@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb",
			"", "not pinned"},
		{"root user", "USER 65534:65534", "USER root", "unprivileged"},
		{"numeric root", "USER 65534:65534", "USER 0:0", "unprivileged"},
		{"no healthcheck", "HEALTHCHECK ", "# ", "HEALTHCHECK"},
	}
	for _, m := range mutations {
		t.Run(m.name, func(t *testing.T) {
			if !strings.Contains(origin, m.old) {
				t.Fatalf("the Dockerfile no longer contains %q", m.old)
			}
			findings := CheckDockerfile([]byte(strings.Replace(origin, m.old, m.new, 1)))
			if len(findings) == 0 {
				t.Fatalf("removing %s was not detected", m.name)
			}
			if !strings.Contains(strings.Join(findings, "\n"), m.want) {
				t.Fatalf("the finding does not mention %q:\n  %s", m.want, strings.Join(findings, "\n  "))
			}
		})
	}
}

func TestDigestsCheckCatchAStaleOrGuessedFile(t *testing.T) {
	digests := readLab(t, "DIGESTS.txt")
	const wafLine = "xammu-lab-waf:1.0.0     image_id=sha256:7ea3616a1070243aaa01c3d7b143ac0d8c05bb5bcaf253a566e04eedf0f1a8be"
	for _, m := range []struct{ name, old, new, want string }{
		{"missing built image", wafLine + "\n", "", "xammu-lab-waf"},
		{"guessed image id", wafLine, "xammu-lab-waf:1.0.0     image_id=not_reported", "image_id"},
		{"missing runner", "  docker.io/curlimages/curl@sha256:", "", "curlimages/curl"},
	} {
		t.Run(m.name, func(t *testing.T) {
			if !strings.Contains(digests, m.old) {
				t.Fatalf("DIGESTS.txt no longer contains %q", m.old)
			}
			findings := CheckDigests([]byte(strings.Replace(digests, m.old, m.new, 1)))
			if len(findings) == 0 {
				t.Fatalf("removing %s was not detected", m.name)
			}
			if !strings.Contains(strings.Join(findings, "\n"), m.want) {
				t.Fatalf("the finding does not mention %q:\n  %s", m.want, strings.Join(findings, "\n  "))
			}
		})
	}
}
