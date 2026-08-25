// Session-establishment orchestration — the first real caller composing
// Cryptography & Keys, Identity, and the Conversations capability client
// into a working send/receive flow (conversations.charter.md §2 of this
// pass's brief). Per CLAUDE.md's "capabilities vs. features," this is
// feature-composition logic, NOT a capability in its own right — it holds
// no capability logic of its own beyond sequencing already-real RPCs in the
// right order, mirroring apps/mobile/src/features/onboarding/onboarding.ts's
// own established role exactly.
import * as crypto from "../../capabilities/crypto";
import * as identity from "../../capabilities/identity";
import * as conversations from "../../capabilities/conversations";
import type { KeyHandle, PrekeyBundle } from "../../capabilities/crypto";
import type { ConversationMessage } from "../../capabilities/conversations";
// Imported from the sessionPayload SUBMODULE directly, not the aggregated
// capabilities/conversations index — deliberately, so this pure byte codec
// stays decoupled from (and testable independently of) the network-calling
// RPC surface `conversations.*` below. See __tests__/session.test.ts.
import { encodeSessionEstablishmentPayload, decodeSessionEstablishmentPayload } from "../../capabilities/conversations/sessionPayload";
import { getCachedSessionHandle, setCachedSessionHandle } from "./localStore";
import { ensureOwnPrekeyIdentity } from "./prekeyLifecycle";
import { appendRows, loadHistory } from "./history";
import type { LocalMessageRow } from "./history";

/**
 * Thrown when the recipient has never published a prekey bundle at all
 * (identity.charter.md §6/§7's named, real edge case — an identity that has
 * never run its first GeneratePrekeyBundle/publish cycle) — surfaced to the
 * UI as "this person hasn't set up messaging yet," never attempted as a
 * silent failure or a generic error.
 */
export class RecipientNotSetUpError extends Error {
  constructor(otherParticipant: string) {
    super(`${otherParticipant} hasn't set up messaging yet.`);
    this.name = "RecipientNotSetUpError";
  }
}

// ---------------------------------------------------------------------------
// sendMessage — composes, per this pass's brief §2:
//
//   1st message in a conversation (no cached session):
//     resolveIdentity -> fetchPrekeyBundle -> deriveSharedSecret (async) ->
//     build session_establishment_payload -> encryptMessage ->
//     createConversation (idempotent by pair) -> sendMessage -> cache handle.
//
//   Subsequent message (session already cached):
//     encryptMessage (cached handle, no payload) -> sendMessage.
// ---------------------------------------------------------------------------

export interface SendMessageParams {
  /** This device's own identityRef — MUST equal the network-verified caller (charter §3's blanket binding). */
  me: string;
  myDeviceId: string;
  /** This process's own registered identity key handle (purpose "sign:identity") — see navigation/types.ts's threading of this value. */
  myPrivateKeyHandle: KeyHandle;
  otherParticipant: string;
  /** Omitted for a not-yet-created conversation — CreateConversation is called lazily, only here, per charter §5. */
  conversationId?: string;
  plaintext: string;
  sessionToken: string;
}

export interface SendMessageResult {
  conversationId: string;
  messageId: string;
  sentAtUnix: number;
}

export async function sendMessage(params: SendMessageParams): Promise<SendMessageResult> {
  const { me, myDeviceId, myPrivateKeyHandle, otherParticipant, plaintext, sessionToken } = params;

  let conversationId = params.conversationId;
  let sharedSecretHandle: KeyHandle | null = conversationId ? await getCachedSessionHandle(conversationId) : null;
  let sessionEstablishmentPayload: Uint8Array | undefined;

  if (!sharedSecretHandle) {
    // No cached session for this conversation (either it doesn't exist yet,
    // or this device has never established one for it) — act as the
    // INITIATOR of a fresh X3DH-style handshake.
    const resolved = await identity.resolveIdentity({ identityRef: otherParticipant });
    const fetched = await identity.fetchPrekeyBundle({ identityRef: otherParticipant }, sessionToken);

    if (fetched.status === "PREKEY_BUNDLE_STATUS_NOT_PUBLISHED") {
      throw new RecipientNotSetUpError(otherParticipant);
    }

    const myPrekeyIdentity = await ensureOwnPrekeyIdentity({ identityRef: me, deviceId: myDeviceId, sessionToken });

    const bundle: PrekeyBundle = {
      identityDhPublicKey: fetched.identityDhPublicKey,
      identityDhPublicKeySignature: fetched.identityDhPublicKeySignature,
      signedPrekey: fetched.signedPrekey,
      oneTimePrekey: fetched.oneTimePrekey,
    };

    const derived = await crypto.deriveSharedSecret({
      privateKeyHandle: myPrivateKeyHandle,
      theirIdentitySigningPublicKey: resolved.publicIdentity.publicKey,
      theirPrekeyBundle: bundle,
    });

    sharedSecretHandle = derived.sharedSecretHandle;
    sessionEstablishmentPayload = encodeSessionEstablishmentPayload({
      ephemeralPublicKey: derived.myEphemeralPublicKey,
      identityDhPublicKey: myPrekeyIdentity.identityDhPublicKey,
      identityDhPublicKeySignature: myPrekeyIdentity.identityDhPublicKeySignature,
      signedPrekeyId: fetched.signedPrekey.prekeyId,
      oneTimePrekeyId: fetched.oneTimePrekey?.prekeyId,
    });
  }

  const { ciphertext } = await crypto.encryptMessage({
    sharedSecretHandle,
    plaintext: new TextEncoder().encode(plaintext),
  });

  if (!conversationId) {
    const created = await conversations.createConversation({ creator: me, participant: otherParticipant }, sessionToken);
    conversationId = created.conversationId;
  }

  const sent = await conversations.sendMessage(
    { conversationId, sender: me, ciphertext, sessionEstablishmentPayload },
    sessionToken,
  );

  // Persist the mapping BEFORE returning — required, not optional (see
  // localStore.ts's own header comment on why an in-memory-only mapping
  // reproduces the exact bug class the crypto amendment fixed one layer
  // down).
  await setCachedSessionHandle(conversationId, sharedSecretHandle);

  // Layer two's local plaintext history (charter §4 Art. 9) is written HERE,
  // at send time, from the plaintext this device already knows — never by
  // later re-decrypting this device's own ciphertext (see history.ts's
  // header comment on why that would use the wrong directional chain).
  await appendRows(conversationId, [
    {
      messageId: sent.messageId,
      sender: me,
      sentAtUnix: sent.sentAtUnix,
      direction: "sent",
      plaintext,
      undecryptable: false,
    },
  ]);

  return { conversationId, messageId: sent.messageId, sentAtUnix: sent.sentAtUnix };
}

// ---------------------------------------------------------------------------
// Receive path — see history.ts's header comment for WHY every message's
// decrypt attempt must happen exactly once, ever: decryptMessage advances a
// one-way ratchet chain and is not idempotent/replayable.
// ---------------------------------------------------------------------------

async function tryDecryptIncoming(params: {
  me: string;
  myPrivateKeyHandle: KeyHandle;
  conversationId: string;
  message: ConversationMessage;
}): Promise<LocalMessageRow> {
  const { conversationId, message } = params;
  const baseRow = { messageId: message.messageId, sender: message.sender, sentAtUnix: message.sentAtUnix };

  try {
    let sharedSecretHandle = await getCachedSessionHandle(conversationId);

    if (!sharedSecretHandle) {
      if (!message.sessionEstablishmentPayload) {
        // charter §5's disclosed, expected gap: no cached session AND no
        // session_establishment_payload — this message predates whatever
        // established a session on this device (or this device was added
        // after it was sent). Not an error to alarm the user over.
        return { ...baseRow, direction: "received", plaintext: null, undecryptable: true };
      }

      const payload = decodeSessionEstablishmentPayload(message.sessionEstablishmentPayload);
      const resolved = await identity.resolveIdentity({ identityRef: message.sender });

      const completed = await crypto.completeSharedSecret({
        privateKeyHandle: params.myPrivateKeyHandle,
        theirIdentityDhPublicKey: payload.identityDhPublicKey,
        theirEphemeralPublicKey: payload.ephemeralPublicKey,
        mySignedPrekeyId: payload.signedPrekeyId,
        myOneTimePrekeyId: payload.oneTimePrekeyId,
        theirIdentitySigningPublicKey: resolved.publicIdentity.publicKey,
        theirIdentityDhPublicKeySignature: payload.identityDhPublicKeySignature,
      });

      sharedSecretHandle = completed.sharedSecretHandle;
      await setCachedSessionHandle(conversationId, sharedSecretHandle);
    }

    const { plaintext } = await crypto.decryptMessage({ sharedSecretHandle, ciphertext: message.ciphertext });
    return { ...baseRow, direction: "received", plaintext: new TextDecoder().decode(plaintext), undecryptable: false };
  } catch {
    // Never throw out of this function — a message that fails to decrypt
    // (bad signature, corrupted payload, AEAD mismatch, an already-consumed
    // one-time prekey from a duplicate delivery, ...) renders as a distinct,
    // clearly-labeled row, never a crash, never blank (this pass's brief §6).
    return { ...baseRow, direction: "received", plaintext: null, undecryptable: true };
  }
}

/**
 * Walks conversations.listMessages' cursor pagination backward, reassembling
 * the FULL ascending-order message history in one call — required, not a
 * convenience: decrypt order must exactly match send order (the ratchet
 * chain only advances forward), so this module never decrypts a page
 * out of the ascending sequence. Mirrors the exact backward-walk-and-prepend
 * algorithm the real server's own test suite proves ListMessages supports
 * (services/api/internal/conversations/service_test.go,
 * TestListMessages_CursorPaginationWalksBackwardThroughFullHistory).
 */
async function listAllMessagesAscending(params: {
  conversationId: string;
  requestingSubject: string;
  sessionToken: string;
}): Promise<ConversationMessage[]> {
  const PAGE_LIMIT = 100;
  const MAX_PAGES = 1000; // bounded loop guard, mirroring the server test's own discipline

  let collected: ConversationMessage[] = [];
  let cursor: string | undefined;

  for (let i = 0; i < MAX_PAGES; i++) {
    const resp = await conversations.listMessages(
      {
        conversationId: params.conversationId,
        requestingSubject: params.requestingSubject,
        beforeMessageId: cursor,
        limit: PAGE_LIMIT,
      },
      params.sessionToken,
    );
    collected = [...resp.messages, ...collected];
    if (!resp.hasMore || resp.messages.length === 0) break;
    cursor = resp.messages[0].messageId;
  }

  return collected;
}

/**
 * Fetches every message this device doesn't already have a local, once-
 * ever-decrypted row for, attempts to decrypt/record each exactly once, and
 * returns the FULL merged local history for `conversationId`, ascending.
 * This device's own sent messages are never re-decrypted (see history.ts's
 * header comment) — if one is somehow missing from local history (a second
 * device, or a cleared local store), it renders as a distinct
 * "not available on this device" row rather than being attempted against
 * the wrong directional chain.
 */
export async function syncThreadHistory(params: {
  me: string;
  myPrivateKeyHandle: KeyHandle;
  conversationId: string;
  sessionToken: string;
}): Promise<LocalMessageRow[]> {
  const existing = await loadHistory(params.conversationId);
  const knownIds = new Set(existing.map((r) => r.messageId));

  const raw = await listAllMessagesAscending({
    conversationId: params.conversationId,
    requestingSubject: params.me,
    sessionToken: params.sessionToken,
  });

  const newRows: LocalMessageRow[] = [];
  for (const message of raw) {
    if (knownIds.has(message.messageId)) continue;

    if (message.sender === params.me) {
      newRows.push({
        messageId: message.messageId,
        sender: message.sender,
        sentAtUnix: message.sentAtUnix,
        direction: "sent",
        plaintext: null,
        undecryptable: true,
      });
      continue;
    }

    newRows.push(
      await tryDecryptIncoming({
        me: params.me,
        myPrivateKeyHandle: params.myPrivateKeyHandle,
        conversationId: params.conversationId,
        message,
      }),
    );
  }

  if (newRows.length === 0) return existing;
  return appendRows(params.conversationId, newRows);
}
