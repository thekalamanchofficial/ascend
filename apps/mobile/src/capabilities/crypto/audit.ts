// PLACEHOLDER pending the real Audit / Explainability capability's client.
//
// That capability has not been implemented yet, so this is deliberately NOT
// a network call — there is nothing to call. Charter obligation (§3,
// "Consumes: Audit / Explainability") requires key generation, rotation,
// and recovery events to be audited: the operation succeeding/failing,
// never the key material itself. This function exists so every call site
// that needs to emit one of those events is already correct and in place;
// wiring in the real Audit client later is a one-line body swap in this
// file, not a redesign or a hunt through the codebase for missing call
// sites.
//
// HARD RULE for every caller in this capability: `metadata` may only ever
// contain operation names, opaque handle strings, public-key fingerprints
// (hashes, not raw keys), purposes, counts, and outcomes. Never key
// material, never plaintext, never a recovery phrase, in any form —
// Art. 8 (privacy) and the charter's §6 threat model apply to this stub
// exactly as they will to the real client.
export function logAuditEvent(action: string, metadata: Record<string, string> = {}): void {
  // eslint-disable-next-line no-undef
  const isDev = typeof __DEV__ !== "undefined" ? __DEV__ : process.env.NODE_ENV !== "production";
  if (isDev) {
    // eslint-disable-next-line no-console
    console.log(`[audit:crypto] ${action}`, metadata);
  }
}
