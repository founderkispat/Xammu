package contracts

import "crypto/sha256"

func sha256Sum(raw []byte) []byte {
	sum := sha256.Sum256(raw)
	return sum[:]
}
