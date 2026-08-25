// Conversations — thin HTTP client for the six real, network-wired RPCs at
// /conversations (services/api/internal/conversations/http.go's Mount() —
// read directly, not assumed: r.Route("/conversations", ...) with POST "/",
// "/messages", "/messages/list", "/list", "/get", "/export", no /v1 prefix,
// matching File Objects' convention, not Identity/SessionAuth's). Per
// apps/mobile/README.md's capability boundary, this module holds no
// capability logic of its own — it never decides who may send/read a
// message; that is services/api/internal/conversations's job
// (Permissions-delegated, per charter §3's Consumes correction). This
// module never imports Cryptography & Keys or Identity — composing this
// client with those two into a real send/receive flow is entirely this
// app's feature-composition layer's job
// (apps/mobile/src/features/conversations/), never this thin client's.
//
// See types.ts's header for the wire-format divergence this file's Wire*
// interfaces encode: PascalCase field names (no json struct tags on the
// real Go types), matching File Objects, not Identity/SessionAuth.
//
// Every route is gated (bearer session token required) AND independently
// checks the identity-bearing field (creator/sender/requestingSubject)
// against the network-verified caller server-side (charter §3's blanket
// caller-identity binding, http.go's ErrCallerMismatch checks) — so every
// function below requires the caller to pass their own known identityRef in
// those fields; there is no ambient-identity path.
import { apiRequest } from "../../api/httpClient";
import { bytesToBase64, base64ToBytes } from "../crypto/bytes";
import { logAuditEvent } from "./audit";
import type {
  ConversationMessage,
  ConversationSummary,
  CreateConversationRequest,
  CreateConversationResponse,
  SendMessageRequest,
  SendMessageResponse,
  ListMessagesRequest,
  ListMessagesResponse,
  ListConversationsRequest,
  ListConversationsResponse,
  GetConversationRequest,
  GetConversationResponse,
  ExportConversationRequest,
  ExportConversationResponse,
} from "./types";

export * from "./types";
export * from "./sessionPayload";

// --- Wire DTOs (PascalCase, base64-string []byte fields), local to this
// file only. Never exported — callers only ever see the camelCase,
// Uint8Array-shaped types from ./types; these exist purely to describe
// what actually goes over HTTP (see types.ts's own header comment). ---

interface WireConversationMessage {
  MessageID: string;
  Sender: string;
  Ciphertext: string;
  SessionEstablishmentPayload: string | null;
  SentAtUnix: number;
}

interface WireConversationSummary {
  ConversationID: string;
  OtherParticipant: string;
  CreatedAtUnix: number;
  LastMessageAtUnix: number;
}

function conversationMessageFromWire(w: WireConversationMessage): ConversationMessage {
  return {
    messageId: w.MessageID,
    sender: w.Sender,
    ciphertext: base64ToBytes(w.Ciphertext),
    sessionEstablishmentPayload: w.SessionEstablishmentPayload ? base64ToBytes(w.SessionEstablishmentPayload) : undefined,
    sentAtUnix: w.SentAtUnix,
  };
}

function conversationSummaryFromWire(w: WireConversationSummary): ConversationSummary {
  return {
    conversationId: w.ConversationID,
    otherParticipant: w.OtherParticipant,
    createdAtUnix: w.CreatedAtUnix,
    lastMessageAtUnix: w.LastMessageAtUnix,
  };
}

// ---------------------------------------------------------------------------
// CreateConversation — idempotent by pair (charter §3): calling this again
// for a pair that already has a conversation returns the existing
// conversationId rather than creating a duplicate. `creator` MUST equal the
// caller's own identityRef (server-enforced, ErrCallerMismatch on
// mismatch). Called LAZILY by the feature-composition layer, only at the
// moment of actually sending the first real message (charter §5) — never
// merely on opening a compose screen. That ordering discipline lives in
// apps/mobile/src/features/conversations/, not here — this function is
// simply the RPC, callable at any time by design (idempotency is what makes
// that safe).
// ---------------------------------------------------------------------------

// ascend:mutates
export async function createConversation(
  request: CreateConversationRequest,
  sessionToken: string,
): Promise<CreateConversationResponse> {
  const resp = await apiRequest<{ ConversationID: string; CreatedAtUnix: number }>("/conversations/", {
    method: "POST",
    bearerToken: sessionToken,
    body: { Creator: request.creator, Participant: request.participant },
  });

  logAuditEvent("conversation_create_requested", { conversationId: resp.ConversationID });

  return { conversationId: resp.ConversationID, createdAtUnix: resp.CreatedAtUnix };
}

// ---------------------------------------------------------------------------
// SendMessage — `ciphertext` is opaque bytes, already encrypted client-side
// by Cryptography & Keys before this call is ever made (charter §3); this
// module never encrypts, never decrypts, never inspects it.
// `sessionEstablishmentPayload` is optional opaque bytes, present only on a
// session-establishing message.
// ---------------------------------------------------------------------------

// ascend:mutates
export async function sendMessage(request: SendMessageRequest, sessionToken: string): Promise<SendMessageResponse> {
  const resp = await apiRequest<{ MessageID: string; SentAtUnix: number }>("/conversations/messages", {
    method: "POST",
    bearerToken: sessionToken,
    body: {
      ConversationID: request.conversationId,
      Sender: request.sender,
      Ciphertext: bytesToBase64(request.ciphertext),
      SessionEstablishmentPayload: request.sessionEstablishmentPayload
        ? bytesToBase64(request.sessionEstablishmentPayload)
        : null,
    },
  });

  // Never log ciphertext or sessionEstablishmentPayload (charter §4 Art. 5's
  // content-free discipline) — only the opaque, already-server-issued
  // conversationId/messageId.
  logAuditEvent("message_send_requested", { conversationId: request.conversationId, messageId: resp.MessageID });

  return { messageId: resp.MessageID, sentAtUnix: resp.SentAtUnix };
}

// ---------------------------------------------------------------------------
// ListMessages — cursor-paginated, ascending. Omitting beforeMessageId
// returns the MOST RECENT page (still ascending within that page); passing
// a prior page's oldest messageId walks backward through history
// (verified against the real server's tests — see types.ts's doc comment).
// Gated to conversation participants only; a non-participant/nonexistent
// conversationId both produce an indistinguishable 403 ApiError (charter
// §3/§6) — callers should treat ANY 403 here as "hide the affordance", the
// same discipline fileobjects.listFileAccess's callers already follow.
// Deliberately not marked ascend:mutates — a read, like listFileObjects.
// ---------------------------------------------------------------------------
export async function listMessages(
  request: ListMessagesRequest,
  sessionToken: string,
): Promise<ListMessagesResponse> {
  const resp = await apiRequest<{ Messages: WireConversationMessage[] | null; HasMore: boolean }>(
    "/conversations/messages/list",
    {
      method: "POST",
      bearerToken: sessionToken,
      body: {
        ConversationID: request.conversationId,
        RequestingSubject: request.requestingSubject,
        BeforeMessageID: request.beforeMessageId ?? null,
        Limit: request.limit,
      },
    },
  );

  return { messages: (resp.Messages ?? []).map(conversationMessageFromWire), hasMore: resp.HasMore };
}

// ---------------------------------------------------------------------------
// ListConversations — self-only inbox (charter §3). `requestingSubject`
// MUST equal the caller's own identityRef (server-enforced at the ONLY
// authorization layer this RPC has — see http.go's handleListConversations
// doc comment). No message preview field exists on this response at all —
// a client-side preview, if built, comes entirely from this device's own
// already-decrypted local history (feature-composition layer), never from
// this RPC. Deliberately not marked ascend:mutates — a read.
// ---------------------------------------------------------------------------
export async function listConversations(
  request: ListConversationsRequest,
  sessionToken: string,
): Promise<ListConversationsResponse> {
  const resp = await apiRequest<{ Conversations: WireConversationSummary[] | null }>("/conversations/list", {
    method: "POST",
    bearerToken: sessionToken,
    body: { RequestingSubject: request.requestingSubject },
  });

  return { conversations: (resp.Conversations ?? []).map(conversationSummaryFromWire) };
}

// ---------------------------------------------------------------------------
// GetConversation — participant-only gated, same nonexistent-vs-not-a-
// participant indistinguishability discipline as listMessages above.
// Deliberately not marked ascend:mutates — a read.
// ---------------------------------------------------------------------------
export async function getConversation(
  request: GetConversationRequest,
  sessionToken: string,
): Promise<GetConversationResponse> {
  const resp = await apiRequest<{ ConversationID: string; Participants: string[] | null; CreatedAtUnix: number }>(
    "/conversations/get",
    {
      method: "POST",
      bearerToken: sessionToken,
      body: { ConversationID: request.conversationId, RequestingSubject: request.requestingSubject },
    },
  );

  return { conversationId: resp.ConversationID, participants: resp.Participants ?? [], createdAtUnix: resp.CreatedAtUnix };
}

// ---------------------------------------------------------------------------
// ExportConversation — charter §3/§4 Art. 9, LAYER ONE only (this
// capability's own stored bytes, byte-for-byte — never a decryptability
// promise; see types.ts's doc comment). Marked ascend:mutates for this
// client-side dev-visibility stub's purposes only (mirroring File Objects'
// exportFile precedent, Art. 16 consistency), even though the real
// server-side charter frames this as a gated read, not a lifecycle mutation.
// LAYER TWO (the guaranteed-readable local transcript) is a completely
// separate function in the feature-composition layer
// (apps/mobile/src/features/conversations/localHistory.ts) — never this one.
// ---------------------------------------------------------------------------

// ascend:mutates
export async function exportConversation(
  request: ExportConversationRequest,
  sessionToken: string,
): Promise<ExportConversationResponse> {
  const resp = await apiRequest<{ ExportBlob: string; FormatVersion: string }>("/conversations/export", {
    method: "POST",
    bearerToken: sessionToken,
    body: { ConversationID: request.conversationId, RequestingSubject: request.requestingSubject },
  });

  logAuditEvent("conversation_exported", { conversationId: request.conversationId, formatVersion: resp.FormatVersion });

  return { exportBlob: base64ToBytes(resp.ExportBlob), formatVersion: resp.FormatVersion };
}
