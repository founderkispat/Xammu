package main

import (
	"testing"
)

// FuzzDecodeHexKey covers the trust file parser: a reviewer's key comes from a
// path the tool did not write, so arbitrary text must be refused by a rule and an
// accepted value must be exactly one Ed25519 public key.
func FuzzDecodeHexKey(f *testing.F) {
	f.Add("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n")
	f.Add("ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789")
	f.Add("ed25519:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	f.Add("00")
	f.Add("")
	f.Add("000102030405060708090a0b0c0d0e0f 101112131415161718191a1b1c1d1e1f")

	f.Fuzz(func(t *testing.T, text string) {
		key, err := decodeHexKey(text)
		if err != nil {
			return
		}
		if len(key) != 32 {
			t.Fatalf("accepted a %d-byte trusted key: %q", len(key), text)
		}
	})
}
