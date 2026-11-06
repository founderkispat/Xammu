// Package labcheck verifies the hardening invariants of the laboratory fixture
// without Docker and without a YAML library. The compose file uses anchors and
// aliases on purpose; internal/yamlish refuses them, so this checker reads
// unambiguous tokens line by line instead of pretending to interpret YAML. It
// catches the loss of a control, not every way a compose file could be written.
package labcheck

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// line is one logical line of a compose file or Dockerfile. Indentation is the
// only structure this checker relies on, and it is enough for the blocks the
// fixture uses.
type line struct {
	num    int
	indent int
	text   string
}

func parseLines(raw string) []line {
	var out []line
	for i, l := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		l = strings.TrimRight(l, " \t\r")
		trimmed := strings.TrimLeft(l, " \t")
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if j := strings.Index(trimmed, " #"); j >= 0 {
			trimmed = strings.TrimRight(trimmed[:j], " \t")
		}
		out = append(out, line{num: i + 1, indent: len(l) - len(trimmed), text: trimmed})
	}
	return out
}

func blockHas(lines []line, needle string) bool {
	for _, l := range lines {
		if strings.Contains(l.text, needle) {
			return true
		}
	}
	return false
}

func blockHasKey(lines []line, key string) bool {
	for _, l := range lines {
		if strings.HasPrefix(l.text, key) {
			return true
		}
	}
	return false
}

// topLevelBlock returns the lines nested under a top-level key, up to the next
// key at column zero. The key line may carry an anchor (`x-lab-defaults: &x`).
func topLevelBlock(lines []line, key string) ([]line, bool) {
	for i, l := range lines {
		if l.indent != 0 || !strings.HasPrefix(l.text, key) {
			continue
		}
		var block []line
		for _, next := range lines[i+1:] {
			if next.indent == 0 {
				break
			}
			block = append(block, next)
		}
		return block, true
	}
	return nil, false
}

// serviceBlocks splits the services section by its two-space keys.
func serviceBlocks(lines []line) map[string][]line {
	block, ok := topLevelBlock(lines, "services:")
	if !ok {
		return nil
	}
	out := map[string][]line{}
	var current string
	for _, l := range block {
		if l.indent == 2 && strings.HasSuffix(l.text, ":") {
			current = strings.TrimSuffix(l.text, ":")
			out[current] = nil
			continue
		}
		if current != "" {
			out[current] = append(out[current], l)
		}
	}
	return out
}

// CheckCompose reports the hardening invariants of lab/compose.yaml that are
// missing. An empty result means every invariant the fixture claims is still
// written down in the file.
func CheckCompose(raw []byte) []string {
	lines := parseLines(string(raw))
	var out []string
	add := func(format string, args ...any) { out = append(out, fmt.Sprintf(format, args...)) }

	if !blockHas(lines, "internal: true") {
		add("networks: no `internal: true`; the lab network would stop being isolated from the host")
	}

	defaults, ok := topLevelBlock(lines, "x-lab-defaults:")
	if !ok {
		add("compose: the x-lab-defaults anchor block is missing, so no service inherits the hardening")
	} else {
		for _, want := range []struct{ needle, message string }{
			{"read_only: true", "x-lab-defaults: no `read_only: true`; the container root would be writable"},
			{"cap_drop:", "x-lab-defaults: no `cap_drop`; the container would keep default capabilities"},
			{"- ALL", "x-lab-defaults: cap_drop does not drop ALL"},
			{"no-new-privileges:true", "x-lab-defaults: no `no-new-privileges:true`"},
			{"pids_limit:", "x-lab-defaults: no `pids_limit`; a runaway loop could exhaust the daemon"},
			{"tmpfs:", "x-lab-defaults: no `tmpfs`; a read-only root would leave no writable space"},
			{"logging:", "x-lab-defaults: no `logging` block; container logs would be unbounded"},
			{"max-size:", "x-lab-defaults: logging has no `max-size`"},
			{"max-file:", "x-lab-defaults: logging has no `max-file`"},
		} {
			if !blockHas(defaults, want.needle) {
				add("%s", want.message)
			}
		}
	}

	services := serviceBlocks(lines)
	if len(services) == 0 {
		add("compose: no services block could be read")
		return out
	}
	for _, name := range sortedKeys(services) {
		block := services[name]
		if !blockHas(block, "<<: *lab-defaults") {
			add("service %s: does not include `<<: *lab-defaults`", name)
		}
		for _, forbidden := range []struct{ key, why string }{
			{"ports:", "would publish the lab beyond its internal network"},
			{"network_mode:", "would replace the isolated network"},
			{"privileged:", "would give the container host-level privileges"},
			{"pid:", "would share the host PID namespace"},
			{"volumes:", "would mount host paths into the fixture"},
		} {
			if blockHasKey(block, forbidden.key) {
				add("service %s: declares `%s`, which %s", name, forbidden.key, forbidden.why)
			}
		}
	}
	netrunner, ok := services["netrunner"]
	if !ok {
		add("compose: no netrunner service, so no probe runner is declared")
	} else if !blockHasKey(netrunner, "user:") {
		add("service netrunner: no `user:`; the probe runner would execute as root")
	}
	return out
}

func sortedKeys(m map[string][]line) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// CheckDockerfile reports whether every stage is built from a digest-pinned
// image, the final image runs unprivileged and the image declares a healthcheck.
func CheckDockerfile(raw []byte) []string {
	lines := parseLines(string(raw))
	var out []string
	add := func(format string, args ...any) { out = append(out, fmt.Sprintf(format, args...)) }
	var sawFrom, sawUser, sawHealth bool
	for _, l := range lines {
		fields := strings.Fields(l.text)
		if len(fields) == 0 {
			continue
		}
		switch strings.ToUpper(fields[0]) {
		case "FROM":
			sawFrom = true
			image := ""
			for _, f := range fields[1:] {
				if !strings.HasPrefix(f, "--") {
					image = f
					break
				}
			}
			if !pinned(image) {
				add("line %d: FROM %q is not pinned by @sha256:<64 hex>", l.num, image)
			}
		case "USER":
			sawUser = true
			if len(fields) < 2 || isRoot(fields[1]) {
				add("line %d: USER does not name an unprivileged user", l.num)
			}
		case "HEALTHCHECK":
			sawHealth = true
		}
	}
	if !sawFrom {
		add("Dockerfile has no FROM line")
	}
	if !sawUser {
		add("Dockerfile has no USER line; the image would run as root")
	}
	if !sawHealth {
		add("Dockerfile has no HEALTHCHECK; compose could not gate on readiness")
	}
	return out
}

var sha256Pin = regexp.MustCompile(`^[0-9a-f]{64}$`)

func pinned(image string) bool {
	at := strings.LastIndex(image, "@sha256:")
	return at > 0 && sha256Pin.MatchString(image[at+len("@sha256:"):])
}

func isRoot(user string) bool {
	u := strings.ToLower(user)
	if u == "root" {
		return true
	}
	uid, _, _ := strings.Cut(u, ":")
	return uid == "0"
}

var (
	digestRunner = regexp.MustCompile(`(?m)^\s+docker\.io/curlimages/curl@sha256:[0-9a-f]{64}\s*$`)
)

// CheckDigests reports whether DIGESTS.txt still records both built images by
// content-addressed ID and the runner by digest. The manifest digest may be
// `not_reported`; the image_id may not, because that is what verify.sh compares.
func CheckDigests(raw []byte) []string {
	text := string(raw)
	var out []string
	for _, image := range []string{"xammu-lab-origin:1.0.0", "xammu-lab-waf:1.0.0"} {
		pattern := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(image) + `\s+image_id=sha256:[0-9a-f]{64}\s*$`)
		if !pattern.MatchString(text) {
			out = append(out, fmt.Sprintf("%s is not recorded with image_id=sha256:<64 hex>", image))
		}
	}
	if !digestRunner.MatchString(text) {
		out = append(out, "the netrunner image is not recorded as docker.io/curlimages/curl@sha256:<64 hex>")
	}
	return out
}
