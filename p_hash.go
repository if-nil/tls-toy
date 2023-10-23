package tls_toy

import (
	"crypto/hmac"
	"hash"
)

// pHash implements the P_hash function, as defined in RFC 4346, Section 5.
func pHash(result, secret, label, seed []byte, hash func() hash.Hash) {
	labelAndSeed := make([]byte, len(label)+len(seed))
	copy(labelAndSeed, label)
	copy(labelAndSeed[len(label):], seed)
	h := hmac.New(hash, secret)
	h.Write(labelAndSeed)
	a := h.Sum(nil)

	j := 0
	for j < len(result) {
		h.Reset()
		h.Write(a)
		h.Write(labelAndSeed)
		b := h.Sum(nil)
		copy(result[j:], b)
		j += len(b)

		h.Reset()
		h.Write(a)
		a = h.Sum(nil)
	}
}
