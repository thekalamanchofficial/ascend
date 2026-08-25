// Local, on-device, ALREADY-DECRYPTED message history — conversations.charter.md
// §4 Art. 9 / §6 "Local plaintext at rest": "the on-device, already-decrypted
// message store this charter's export design depends on MUST use
// Cryptography & Keys' SecureLocalStore/SecureLocalRetrieve — never
// AsyncStorage, never a plain SQLite table." This module is that store.
//
// Why this exists at all, not just "call decryptMessage again next time the
// thread is opened": Cryptography & Keys' EncryptMessage/DecryptMessage
// (crypto/index.ts) implement a real, forward-secret, one-way symmetric
// ratchet chain — decrypting a given ciphertext ADVANCES the receiving
// chain's key and is NOT idempotent/replayable. Attempting to decrypt the
// SAME message a second time would derive the wrong (next) message key and
// fail with an AEAD tag mismatch, incorrectly rendering a message that
// decrypted successfully once as "can't be decrypted" on a later view. This
// module exists precisely to make every message's decrypt attempt happen
// EXACTLY ONCE, ever, on this device, regardless of how many times the
// thread screen is reopened — see session.ts's syncThreadHistory, the only
// writer of new rows into this store.
//
// A message this device sent itself is NEVER re-decrypted at all (its
// plaintext is known at send time and written directly here, in the same
// call that sends it — see session.ts's sendMessage) — attempting to
// decryptMessage a self-sent ciphertext would use the WRONG (receiving,
// not sending) directional chain and fail by construction (charter
// cross-ref: cryptography-and-keys.charter.md's directional
// sendingChainKey/receivingChainKey fix, 2026-08-23).
import { secureLocalStore, secureLocalRetrieve } from "../../capabilities/crypto/secureStore";
import { withKeyLock } from "./mutex";

export interface LocalMessageRow {
  messageId: string;
  sender: string;
  sentAtUnix: number;
  direction: "sent" | "received";
  /** `null` exactly when `undecryptable` is true. */
  plaintext: string | null;
  /**
   * True for: (a) a received message this device could not decrypt (no
   * cached session AND no session_establishment_payload — charter §5's
   * disclosed "message from before this device was added" gap, or a
   * completion/decrypt failure), or (b) a message this device itself sent
   * from elsewhere / before this device's own local history existed, which
   * this device deliberately never attempts to decrypt (see module header).
   */
  undecryptable: boolean;
}

function historyStorageKey(conversationId: string): string {
  return `ascend.conversations.history.${conversationId}`;
}

export async function loadHistory(conversationId: string): Promise<LocalMessageRow[]> {
  try {
    const raw = await secureLocalRetrieve(historyStorageKey(conversationId));
    return JSON.parse(new TextDecoder().decode(raw)) as LocalMessageRow[];
  } catch {
    return [];
  }
}

/**
 * Merges `newRows` into this conversation's persisted history (deduped by
 * `messageId`, existing rows always win over a same-id newcomer — a row,
 * once written, is never rewritten, matching the "exactly once, ever"
 * discipline this module's header describes), keeps the result sorted
 * ascending by `sentAtUnix`, persists it, and returns the merged list.
 *
 * LOCKED per `conversationId` (Security Steward implementation-merge-gate
 * veto, 2026-08-25 — see docs/DECISION_LOG.md): this function's own
 * `secureLocalRetrieve` -> merge-in-JS -> `secureLocalStore` sequence has a
 * real `await` boundary in the middle, and two concretely reachable
 * triggers can call it concurrently for the SAME conversationId — a
 * compose screen whose Send button isn't disabled during an in-flight
 * background `syncThreadHistory` (session.ts), and navigating away from a
 * screen mid-sync, which doesn't cancel the in-flight promise chain.
 * Without a lock, the loser's write would silently clobber the winner's —
 * an already-decrypted message (one that, per this module's own header
 * comment, can never be decrypted again) could vanish from local history
 * with no error, no audit event, no user-visible sign. `withKeyLock`
 * (mirroring `keyRegistry.ts`'s `withRatchetSessionLock`/
 * `prekeyStore.ts`'s `withOneTimePrekeyLock`) serializes the full
 * retrieve-merge-store sequence per `conversationId` — safe to key this way
 * (rather than a single global lock, as `localStore.ts`'s session map
 * uses) since each conversation has its own, independent storage key;
 * concurrent writes to DIFFERENT conversations never block each other.
 */
export async function appendRows(conversationId: string, newRows: LocalMessageRow[]): Promise<LocalMessageRow[]> {
  if (newRows.length === 0) return loadHistory(conversationId);

  return withKeyLock(conversationId, async () => {
    const existing = await loadHistory(conversationId);
    const knownIds = new Set(existing.map((r) => r.messageId));
    const merged = [...existing];
    for (const row of newRows) {
      if (knownIds.has(row.messageId)) continue;
      knownIds.add(row.messageId);
      merged.push(row);
    }
    merged.sort((a, b) => a.sentAtUnix - b.sentAtUnix);

    await secureLocalStore(historyStorageKey(conversationId), new TextEncoder().encode(JSON.stringify(merged)));
    return merged;
  });
}

// ---------------------------------------------------------------------------
// Layer TWO of conversations.charter.md §4 Art. 9's two-layer export design
// — the RECOMMENDED, guaranteed-readable export, built from this device's
// own already-decrypted local history. Distinct from (and, per the charter,
// never to be confused in UI copy with) Conversations'
// `exportConversation` RPC, which returns the server's own stored
// ciphertext bytes with NO decryptability guarantee. Requires an explicit
// user-confirmation step before producing it, mirroring
// `crypto.exportKeyMaterial`'s `user_confirmation` gate — this is a full
// plaintext transcript leaving the app's own encrypted-at-rest boundary,
// the same sensitivity class that gate exists for.
// ---------------------------------------------------------------------------

const LOCAL_EXPORT_FORMAT_VERSION = "ascend-conversations-local-export-v1";

export interface LocalTranscriptExport {
  exportBlob: Uint8Array;
  formatVersion: string;
}

export function buildLocalTranscriptExport(params: {
  conversationId: string;
  otherParticipant: string;
  rows: LocalMessageRow[];
  userConfirmation: boolean;
}): LocalTranscriptExport {
  if (!params.userConfirmation) {
    throw new Error("buildLocalTranscriptExport requires explicit user_confirmation; refusing a silent export.");
  }

  const payload = {
    formatVersion: LOCAL_EXPORT_FORMAT_VERSION,
    exportedAt: new Date().toISOString(),
    conversationId: params.conversationId,
    otherParticipant: params.otherParticipant,
    // Honest framing: this is THIS DEVICE's own decrypted view, not a
    // platform-wide guarantee — a message this device could never decrypt
    // is included as an explicit gap marker, never silently omitted (Art. 5
    // "nothing important happens silently" applies to an export's
    // completeness claims too).
    messages: params.rows.map((r) => ({
      messageId: r.messageId,
      sender: r.sender,
      sentAtUnix: r.sentAtUnix,
      direction: r.direction,
      text: r.undecryptable ? null : r.plaintext,
      undecryptableOnThisDevice: r.undecryptable,
    })),
  };

  const exportBlob = new TextEncoder().encode(JSON.stringify(payload, null, 2));
  return { exportBlob, formatVersion: LOCAL_EXPORT_FORMAT_VERSION };
}
