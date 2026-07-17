package storage

import "testing"

func TestSealOpenOuterEnvelope_Roundtrip(t *testing.T) {
	key, err := generateWrappingKey()
	if err != nil {
		t.Fatalf("generateWrappingKey: %v", err)
	}
	plaintext := []byte("opaque ciphertext from Storage's point of view")

	sealed, err := sealOuterEnvelope(key, plaintext)
	if err != nil {
		t.Fatalf("sealOuterEnvelope: %v", err)
	}
	if string(sealed) == string(plaintext) {
		t.Fatalf("sealed output must not equal the input")
	}

	opened, err := openOuterEnvelope(key, sealed)
	if err != nil {
		t.Fatalf("openOuterEnvelope: %v", err)
	}
	if string(opened) != string(plaintext) {
		t.Fatalf("roundtrip mismatch: got %q, want %q", opened, plaintext)
	}
}

// TestOpenOuterEnvelope_WrongKeyFails is the core proof behind the
// crypto-shred deletion guarantee: without the correct wrapping key, the
// sealed bytes are not decryptable — not merely "harder to read."
func TestOpenOuterEnvelope_WrongKeyFails(t *testing.T) {
	key, err := generateWrappingKey()
	if err != nil {
		t.Fatalf("generateWrappingKey: %v", err)
	}
	wrongKey, err := generateWrappingKey()
	if err != nil {
		t.Fatalf("generateWrappingKey: %v", err)
	}
	plaintext := []byte("some opaque ciphertext")

	sealed, err := sealOuterEnvelope(key, plaintext)
	if err != nil {
		t.Fatalf("sealOuterEnvelope: %v", err)
	}

	if _, err := openOuterEnvelope(wrongKey, sealed); err == nil {
		t.Fatalf("expected openOuterEnvelope to fail with the wrong key, it did not")
	}

	// A destroyed (zeroed) key must also fail to open — this is exactly
	// what DeleteBlob's crypto-shred path relies on.
	zeroed := make([]byte, wrappingKeySize)
	if _, err := openOuterEnvelope(zeroed, sealed); err == nil {
		t.Fatalf("expected openOuterEnvelope to fail with a zeroed key, it did not")
	}
}

func TestOpenOuterEnvelope_TamperedCiphertextFails(t *testing.T) {
	key, err := generateWrappingKey()
	if err != nil {
		t.Fatalf("generateWrappingKey: %v", err)
	}
	sealed, err := sealOuterEnvelope(key, []byte("some opaque ciphertext"))
	if err != nil {
		t.Fatalf("sealOuterEnvelope: %v", err)
	}
	tampered := append([]byte(nil), sealed...)
	tampered[len(tampered)-1] ^= 0xFF // flip the last byte (inside the GCM tag)

	if _, err := openOuterEnvelope(key, tampered); err == nil {
		t.Fatalf("expected openOuterEnvelope to reject tampered ciphertext, it did not")
	}
}

func TestZeroBytes(t *testing.T) {
	b := []byte{1, 2, 3, 4}
	zeroBytes(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("byte %d not zeroed: %d", i, v)
		}
	}
}

func TestWrappingKeyFingerprint_NeverContainsRawKeyBytes(t *testing.T) {
	key, err := generateWrappingKey()
	if err != nil {
		t.Fatalf("generateWrappingKey: %v", err)
	}
	fp := wrappingKeyFingerprint(key)
	if fp == "" {
		t.Fatalf("expected a non-empty fingerprint")
	}
	// The fingerprint must never simply be the key's own hex encoding —
	// it must be a one-way digest, not a re-encoding.
	for i := 0; i < len(key)-4; i++ {
		window := key[i : i+4]
		if string(window) != "" && hexContains(fp, window) {
			// Extremely unlikely for a real SHA-256 digest to
			// accidentally contain 4 raw key bytes' hex form; this guards
			// against a regression to the earlier (rejected) "copy raw
			// bytes" implementation.
			t.Fatalf("fingerprint appears to leak raw key bytes")
		}
	}
}

func hexContains(s string, b []byte) bool {
	// Minimal helper: encode b to hex and check substring containment.
	const hextable = "0123456789abcdef"
	enc := make([]byte, len(b)*2)
	for i, v := range b {
		enc[i*2] = hextable[v>>4]
		enc[i*2+1] = hextable[v&0x0f]
	}
	needle := string(enc)
	for i := 0; i+len(needle) <= len(s); i++ {
		if s[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
