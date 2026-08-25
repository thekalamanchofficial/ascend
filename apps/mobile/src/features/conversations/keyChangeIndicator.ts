// Passive key-rotation/change indicator — see localStore.ts's own header
// comment for the storage primitive this builds on, and
// ConversationThreadScreen.tsx's header comment for the scope decision this
// pass made (real, but narrow: covers a changed IDENTITY SIGNING key
// detected via ResolveIdentity, does NOT cover the exhaustion-fallback
// "session established without a one-time prekey" second trigger condition
// cryptography-and-keys.charter.md §5 also names, since that signal is
// internal to the crypto module's own event stream — see this pass's report
// for why that's named as a follow-up rather than built here).
import { bytesEqual } from "../../capabilities/crypto/bytes";
import { getLastSeenIdentitySigningPublicKey, setLastSeenIdentitySigningPublicKey } from "./localStore";

/**
 * Compares `currentPublicKey` against whatever this device last saw for
 * `identityRef`, updates the cache to `currentPublicKey` regardless, and
 * returns whether this is a CHANGE from a previously-seen value (never true
 * on first-ever contact — that's ordinary TOFU, not a rotation).
 */
export async function checkAndRecordIdentityKeyChange(
  identityRef: string,
  currentPublicKey: Uint8Array,
): Promise<boolean> {
  const lastSeen = await getLastSeenIdentitySigningPublicKey(identityRef);
  await setLastSeenIdentitySigningPublicKey(identityRef, currentPublicKey);
  if (!lastSeen) return false;
  return !bytesEqual(lastSeen, currentPublicKey);
}
