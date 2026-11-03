package contracts

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
)

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// NewUUID returns a random (v4) identifier.
func NewUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("contracts: cannot generate identifier: %v", err))
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// IsUUID reports whether s is a canonical lowercase v4 UUID.
func IsUUID(s string) bool { return uuidRE.MatchString(s) }

// NewDigest renders a content hash in the canonical transport form.
func NewDigest(raw []byte) string {
	return "sha256:" + hex.EncodeToString(sha256Sum(raw))
}

func digestField(c *Violations, field, got string) {
	if got == "" {
		c.add(field, "required")
		return
	}
	if !digestRE.MatchString(got) {
		c.add(field, "must be sha256:<64 lowercase hex>, got "+got)
	}
}

func uuidField(c *Violations, field, got string) {
	if got == "" {
		c.add(field, "required")
		return
	}
	if !IsUUID(got) {
		c.add(field, "must be a canonical v4 UUID, got "+got)
	}
}

func itoaSimple(n int) string { return strconv.Itoa(n) }
