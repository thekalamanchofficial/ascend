-- 0011_conversations: Conversations' durable conversation/message store.
--
-- Every column maps 1:1 onto a field this capability already persists on
-- Conversation/Message (internal/conversations/types.go, both marked
-- // ascend:persisted) and onto internal/conversations/DATA_MANIFEST.md's
-- documented fields (Art. 8).
--
-- conversations: participant_lo/participant_hi store the two participants
-- in CANONICAL (lexicographically sorted) order, never creator/participant
-- order — this is what lets a single UNIQUE index enforce "at most one
-- conversation per unordered pair" regardless of which caller is creator
-- vs participant on any given CreateConversation call (charter §3's
-- idempotent-by-pair requirement). See
-- internal/conversations/postgres_store.go's findOrCreateConversation for
-- the single atomic statement this schema backs.
--
-- messages: ciphertext/session_establishment_payload are BYTEA — opaque,
-- already-encrypted bytes this capability's backend never parses, never
-- decrypts, and structurally cannot (charter §6; see
-- internal/conversations/ciphertext_leak_test.go for the mechanical proof).
-- seq (BIGSERIAL) is a pure internal ordering column, mirroring
-- fileobjects_versions'/fileobjects_events' own seq columns — never
-- returned by any Store method's exported shape or any RPC response, only
-- used in ORDER BY, backing ListMessages' before_message_id cursor
-- (charter §3) since message_id itself (an opaque crypto/rand ref) is not
-- sortable.
--
-- See docs/DECISION_LOG.md, "Conversations: two-table Postgres schema",
-- "Conversations: CreateConversation's atomic find-or-create query", and
-- "Conversations: message ordering via an internal seq column" for the
-- full design rationale.

CREATE TABLE IF NOT EXISTS conversations (
    conversation_id   TEXT NOT NULL PRIMARY KEY,
    participant_lo    TEXT NOT NULL,
    participant_hi    TEXT NOT NULL,
    created_at_unix    BIGINT NOT NULL,
    CONSTRAINT conversations_pair_distinct CHECK (participant_lo <> participant_hi)
);

-- The load-bearing constraint for CreateConversation's idempotent-by-pair
-- guarantee (charter §3) — see postgres_store.go's findOrCreateConversation,
-- whose ON CONFLICT (participant_lo, participant_hi) clause depends on
-- exactly this index existing.
CREATE UNIQUE INDEX IF NOT EXISTS idx_conversations_pair ON conversations (participant_lo, participant_hi);

-- Back ListConversations' "WHERE participant_lo = $1 OR participant_hi = $1"
-- query (postgres_store.go's conversationSummariesForSubject).
CREATE INDEX IF NOT EXISTS idx_conversations_participant_lo ON conversations (participant_lo);
CREATE INDEX IF NOT EXISTS idx_conversations_participant_hi ON conversations (participant_hi);

CREATE TABLE IF NOT EXISTS messages (
    message_id                      TEXT NOT NULL PRIMARY KEY,
    conversation_id                  TEXT NOT NULL REFERENCES conversations (conversation_id),
    sender                            TEXT NOT NULL,
    ciphertext                        BYTEA NOT NULL,
    session_establishment_payload     BYTEA,
    sent_at_unix                      BIGINT NOT NULL,
    seq                               BIGSERIAL NOT NULL
);

-- Backs listMessages' (conversation_id, seq) ordering/pagination and
-- allMessagesForConversation's full-history read, both ORDER BY seq.
CREATE INDEX IF NOT EXISTS idx_messages_conversation_seq ON messages (conversation_id, seq);

-- Least-privilege runtime role. Like 0001_audit_events, ascend_app is never
-- CREATEd here — it already exists, created idempotently by migration 0001.
--
-- conversations: SELECT/INSERT for normal operation, plus DELETE — but
-- DELETE is granted ONLY to back deleteConversationRecord, CreateConversation's
-- own rollback-only plumbing for its partial-bootstrap-failure path
-- (internal/conversations/store.go's Store interface doc comment); there is
-- no public DeleteConversation RPC in this charter's freeze.
--
-- messages: SELECT/INSERT only — append-only by design, mirroring
-- audit_events' own precedent (0001_audit_events.up.sql): no
-- DeleteMessage/UpdateMessage RPC exists anywhere in this charter, and
-- CreateConversation's rollback path never needs to touch messages (it only
-- ever fires before any message could have been sent to the
-- brand-new conversation it's rolling back).
GRANT SELECT, INSERT, DELETE ON conversations TO ascend_app;
GRANT SELECT, INSERT ON messages TO ascend_app;
GRANT USAGE, SELECT ON SEQUENCE messages_seq_seq TO ascend_app;

REVOKE UPDATE ON conversations FROM ascend_app;
REVOKE UPDATE, DELETE ON messages FROM ascend_app;
REVOKE UPDATE, DELETE ON messages FROM PUBLIC;
