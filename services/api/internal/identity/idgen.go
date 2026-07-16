package identity

import (
	"crypto/rand"
	"fmt"
)

// newID generates an RFC 4122 version 4 UUID using crypto/rand (the OS
// CSPRNG), the same "one audited entropy source" discipline Cryptography &
// Keys' decision log entry (2026-07-16) established for the mobile side.
// No external UUID dependency is added deliberately — this package has no
// network access guaranteed at build time in every environment it might be
// built in, and a version-4 UUID is a ~15-line primitive that does not
// justify a third-party dependency for a Go backend service.
func newID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failing indicates a broken host CSPRNG — there is no
		// safe way to continue issuing identifiers at that point.
		panic("identity: crypto/rand unavailable: " + err.Error())
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
