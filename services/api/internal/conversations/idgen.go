package conversations

import (
	"crypto/rand"
	"encoding/hex"
)

// generateConversationID/generateMessageID return fresh, opaque handles —
// "conv_"/"msg_" followed by 32 hex characters (16 random bytes) from
// crypto/rand (the OS CSPRNG), mirroring fileobjects.generateFileObjectID's
// convention exactly. Neither is ever derived from or contains any part of
// a participant's identity_ref, sender, ciphertext, or session
// establishment payload.
func generateConversationID() (string, error) {
	return generateRef("conv_")
}

func generateMessageID() (string, error) {
	return generateRef("msg_")
}

func generateRef(prefix string) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(b), nil
}
