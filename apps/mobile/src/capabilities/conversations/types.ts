// Conversations — TypeScript request/response shapes.
//
// Hand-mirrored from the real, frozen Go wire types
// (services/api/internal/conversations/types.go), not generated — same
// established precedent as every other backend capability's mobile client
// in this codebase (see fileobjects/types.ts's own header comment, which
// this file follows field-for-field in spirit).
//
// *** WIRE-FORMAT: PascalCase, verified against real Go source, NOT
// assumed. *** services/api/internal/conversations/types.go's request/
// response structs carry NO `json` struct tags (confirmed by reading that
// file directly) — Go's encoding/json falls back to the exported field
// name verbatim, so the wire format for every Conversations RPC is
// PascalCase (`{"Creator":"...","Participant":"..."}`), matching File
// Objects' convention exactly, NOT Identity/SessionAuth's camelCase one.
// Do not "fix" this to camelCase — that would silently break every request
// against the real server. See index.ts's `Wire*` interfaces (PascalCase,
// local to that file, never exported) for the boundary that converts in
// both directions.
//
// []byte Go fields (Ciphertext, SessionEstablishmentPayload, ExportBlob)
// are base64-encoded JSON strings on the wire, same as every other Go
// []byte field in this codebase. The shapes below are the in-memory,
// already-decoded form (Uint8Array) this module's callers work with.
//
// If the frozen contract changes, that is a charter amendment routed back
// through the Chief Architect — not a change made unilaterally here.

/**
 * Mirrors conversations.ConversationMessage — a message as returned by
 * ListMessages/ExportConversation. `ciphertext` and
 * `sessionEstablishmentPayload` are opaque bytes end to end (charter §6) —
 * this module never parses, decrypts, or interprets them; that is entirely
 * this app's feature-composition layer's job
 * (apps/mobile/src/features/conversations/), consuming Cryptography & Keys
 * and Identity, never this thin client.
 */
export interface ConversationMessage {
  messageId: string;
  sender: string;
  ciphertext: Uint8Array;
  /** Present only on a session-establishing (or re-establishing) message — charter §3. */
  sessionEstablishmentPayload?: Uint8Array;
  sentAtUnix: number;
}

/**
 * Mirrors conversations.ConversationSummary — ListConversations' per-row
 * shape. `lastMessageAtUnix` is ALWAYS derived server-side at query time
 * (charter §3/§4 Art. 8) — never something this module or its caller may
 * treat as authoritative beyond "what the server just computed." Deliberately
 * no message-preview field exists on this shape at all (charter §3) — a
 * preview, if shown, is entirely a client-side concern built from this
 * device's own already-decrypted local history (see the feature layer's
 * `localHistory.ts`), never something this capability's contract offers.
 */
export interface ConversationSummary {
  conversationId: string;
  otherParticipant: string;
  createdAtUnix: number;
  lastMessageAtUnix: number;
}

// --- Request/response DTOs, one per RPC in conversations.proto ---

export interface CreateConversationRequest {
  creator: string;
  participant: string;
}

export interface CreateConversationResponse {
  conversationId: string;
  createdAtUnix: number;
}

export interface SendMessageRequest {
  conversationId: string;
  sender: string;
  ciphertext: Uint8Array;
  /** Only present on a session-establishing message (charter §3) — omit entirely otherwise. */
  sessionEstablishmentPayload?: Uint8Array;
}

export interface SendMessageResponse {
  messageId: string;
  sentAtUnix: number;
}

/**
 * `beforeMessageId` omitted returns the MOST RECENT page (still ascending
 * within that page) — passing a prior page's oldest `messageId` walks
 * backward through history one page at a time (verified against the real
 * server's `service_test.go`: `TestListMessages_AscendingOrderAndDefaultMostRecentPage`
 * / `TestListMessages_CursorPaginationWalksBackwardThroughFullHistory`).
 * `limit` is clamped server-side (default 50, max 200) — this module never
 * assumes its requested value was honored verbatim.
 */
export interface ListMessagesRequest {
  conversationId: string;
  requestingSubject: string;
  beforeMessageId?: string;
  limit: number;
}

export interface ListMessagesResponse {
  messages: ConversationMessage[];
  hasMore: boolean;
}

/** Self-only inventory (charter §3) — `requestingSubject` MUST be the caller's own identityRef; the server independently verifies this against the network-verified bearer-token caller. */
export interface ListConversationsRequest {
  requestingSubject: string;
}

export interface ListConversationsResponse {
  conversations: ConversationSummary[];
}

export interface GetConversationRequest {
  conversationId: string;
  requestingSubject: string;
}

export interface GetConversationResponse {
  conversationId: string;
  participants: string[];
  createdAtUnix: number;
}

/**
 * Layer ONE of this charter's two-layer Art. 9 export design (§4) — this
 * capability's own stored bytes, byte-for-byte, verifiably complete —
 * NEVER a promise the bundle is decryptable (forward secrecy means the
 * decryption key for an old message may no longer exist on ANY device).
 * Layer TWO (the guaranteed-readable, already-decrypted local transcript)
 * is entirely this app's feature-composition layer's concern
 * (`apps/mobile/src/features/conversations/localHistory.ts`) — never
 * conflated with this RPC in any UI copy.
 */
export interface ExportConversationRequest {
  conversationId: string;
  requestingSubject: string;
}

export interface ExportConversationResponse {
  exportBlob: Uint8Array;
  formatVersion: string;
}
