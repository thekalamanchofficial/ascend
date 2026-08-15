package fileobjects

import (
	"crypto/rand"
	"encoding/hex"
)

// generateFileObjectID/generateVersionRef return fresh, opaque handles —
// "fobj_"/"ver_" followed by 32 hex characters (16 random bytes) from
// crypto/rand (the OS CSPRNG), mirroring Storage's generateBlobRef
// convention exactly. Neither is ever derived from or contains any part of
// the file's content, owner, or a blob_ref.
func generateFileObjectID() (string, error) {
	return generateRef("fobj_")
}

func generateVersionRef() (string, error) {
	return generateRef("ver_")
}

func generateRef(prefix string) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(b), nil
}
