// Shared helper for producing safe-to-log identifiers in audit metadata.
//
// Charter §3 ("Consumes: Audit / Explainability" — the operation
// succeeding/failing, never the key material itself) and Art. 8 (privacy —
// minimum data, documented purpose) apply to audit metadata exactly as they
// do to everything else this module touches. A raw value (a public key, a
// SecureLocalStore key *name*, etc.) is never safe to put in audit
// metadata: even a "harmless" local-storage key name can be identifying
// (e.g. `"contact:+15551234567:session-key"`). This truncated SHA-256 hash
// lets two audit events be correlated (same input -> same hash) without the
// raw value being recoverable from the log, so every call site in this
// module — and the real Audit client this stub will eventually be swapped
// for — gets that property for free rather than needing to remember it.
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "./bytes";

export function auditFingerprint(input: string | Uint8Array): string {
  const bytes = typeof input === "string" ? new TextEncoder().encode(input) : input;
  return bytesToHex(sha256(bytes).slice(0, 8));
}
