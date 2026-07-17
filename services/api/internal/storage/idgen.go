package storage

import (
	"crypto/rand"
	"encoding/hex"
)

// generateBlobRef returns a fresh, opaque blob_ref: "blob_" followed by 32
// hex characters (16 random bytes) from crypto/rand (the OS CSPRNG). It is
// never derived from or contains any part of the blob's content, owner, or
// policy — an opaque handle, per the frozen contract's
// StoreBlobResponse.blob_ref.
func generateBlobRef() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "blob_" + hex.EncodeToString(b), nil
}
