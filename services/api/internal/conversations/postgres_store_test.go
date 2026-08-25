package conversations

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/ascend/services/api/internal/platform"
)

// This file exercises PostgresStore against a real Postgres database. It
// assumes internal/platform/migrations/0011_conversations.up.sql has
// already been applied to that database — by `go run .` (main.go runs
// migrations automatically at startup) or by whatever else set up the test
// database. This file deliberately does NOT call platform.RunMigrations
// itself: running migrations is the composition root's job, not a test's.
//
// Gate: every test here is skipped (visibly, via t.Skip) unless
// DATABASE_URL is set. Run `docker compose up -d` from the repo root
// first, with a populated .env (see .env.example), then set DATABASE_URL
// before `go test`. Mirrors internal/fileobjects/postgres_store_test.go's
// identical gate.

func requirePostgres(t *testing.T) string {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL not set; skipping Postgres-backed conversations store tests — run `docker compose up -d` from the repo root first")
	}
	return url
}

func newTestPostgresStore(t *testing.T) *PostgresStore {
	t.Helper()
	url := requirePostgres(t)
	pool, err := platform.NewPostgresPool(context.Background(), url)
	if err != nil {
		t.Fatalf("connecting to postgres (is `docker compose up -d` running, and have migrations been applied?): %v", err)
	}
	t.Cleanup(pool.Close)
	return NewPostgresStore(pool)
}

func uniqueRunID(t *testing.T) string {
	t.Helper()
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("generating unique run id: %v", err)
	}
	return hex.EncodeToString(b[:])
}

// cleanupConversation deletes every row (across both tables) tagged with
// conversationID. messages is append-only for the DATABASE_URL role
// (ascend_app) by design (0011_conversations.up.sql — mirrors
// audit_events' own precedent) — this store's own pool connection cannot
// delete from it, so messages rows are removed via MIGRATIONS_DATABASE_URL
// (the elevated admin connection) instead, exactly like
// internal/audit/postgres_store_test.go's cleanupEvents. If
// MIGRATIONS_DATABASE_URL isn't set, messages cleanup is skipped with a
// logged note — leftover rows are harmless to other tests (each test
// scopes its own reads to a unique run id) but will persist in the
// database. conversations itself IS deletable via DATABASE_URL (this
// package's own rollback-only deleteConversationRecord depends on it), so
// that half of cleanup always runs via the store's own connection, after
// messages (conversations.conversation_id has referencing FK rows in
// messages).
func cleanupConversation(t *testing.T, store *PostgresStore, conversationID string) {
	t.Helper()
	ctx := context.Background()

	adminURL := os.Getenv("MIGRATIONS_DATABASE_URL")
	if adminURL == "" {
		t.Logf("MIGRATIONS_DATABASE_URL not set; skipping cleanup of test messages for conversation %s — messages is append-only for the DATABASE_URL role by design.", conversationID)
	} else if conn, err := pgx.Connect(ctx, adminURL); err != nil {
		t.Logf("cleanup: connecting via MIGRATIONS_DATABASE_URL: %v", err)
	} else {
		if _, err := conn.Exec(ctx, "DELETE FROM messages WHERE conversation_id = $1", conversationID); err != nil {
			t.Logf("cleanup: deleting test messages: %v", err)
		}
		_ = conn.Close(ctx)
	}

	if _, err := store.pool.Exec(ctx, "DELETE FROM conversations WHERE conversation_id = $1", conversationID); err != nil {
		t.Logf("cleanup: deleting test conversation: %v", err)
	}
}

// TestPostgresStore_FindOrCreateConversation_AtomicIdempotentByPair covers
// findOrCreateConversation's central guarantee: a fresh pair inserts
// (created=true); a repeat call for the SAME pair (even with a different
// candidate conversation_id) returns the ORIGINAL row unchanged
// (created=false) — the mechanism CreateConversation's idempotent-by-pair
// behavior (charter §3) depends on.
func TestPostgresStore_FindOrCreateConversation_AtomicIdempotentByPair(t *testing.T) {
	store := newTestPostgresStore(t)
	run := uniqueRunID(t)
	lo, hi := "identity:alice-"+run, "identity:bob-"+run

	firstID := "conv-first-" + run
	rec1, created1 := store.findOrCreateConversation(Conversation{ConversationID: firstID, ParticipantLo: lo, ParticipantHi: hi, CreatedAtUnix: 1000})
	t.Cleanup(func() { cleanupConversation(t, store, firstID) })
	if !created1 {
		t.Fatal("expected created=true for a genuinely fresh pair")
	}
	if rec1.ConversationID != firstID {
		t.Fatalf("expected the candidate's own conversation_id to be used, got %q", rec1.ConversationID)
	}

	secondID := "conv-second-" + run
	rec2, created2 := store.findOrCreateConversation(Conversation{ConversationID: secondID, ParticipantLo: lo, ParticipantHi: hi, CreatedAtUnix: 2000})
	t.Cleanup(func() { cleanupConversation(t, store, secondID) }) // no-op if never inserted
	if created2 {
		t.Fatal("expected created=false for a repeat call against the same pair")
	}
	if rec2.ConversationID != firstID {
		t.Fatalf("expected the ORIGINAL conversation_id (%q) to be returned, got %q", firstID, rec2.ConversationID)
	}
	if rec2.CreatedAtUnix != 1000 {
		t.Fatalf("expected the original created_at_unix (1000) to be preserved, got %d", rec2.CreatedAtUnix)
	}
}

func TestPostgresStore_GetConversation_HitAndMiss(t *testing.T) {
	store := newTestPostgresStore(t)
	run := uniqueRunID(t)
	convID := "conv-" + run
	t.Cleanup(func() { cleanupConversation(t, store, convID) })

	if _, ok := store.getConversation(convID); ok {
		t.Fatal("expected a miss before any findOrCreateConversation call")
	}

	lo, hi := "identity:alice-"+run, "identity:bob-"+run
	if _, created := store.findOrCreateConversation(Conversation{ConversationID: convID, ParticipantLo: lo, ParticipantHi: hi, CreatedAtUnix: 500}); !created {
		t.Fatal("expected created=true")
	}

	got, ok := store.getConversation(convID)
	if !ok {
		t.Fatal("expected a hit")
	}
	if got.ParticipantLo != lo || got.ParticipantHi != hi || got.CreatedAtUnix != 500 {
		t.Fatalf("unexpected record: %+v", got)
	}
}

func TestPostgresStore_DeleteConversationRecord(t *testing.T) {
	store := newTestPostgresStore(t)
	run := uniqueRunID(t)
	convID := "conv-" + run
	lo, hi := "identity:alice-"+run, "identity:bob-"+run
	store.findOrCreateConversation(Conversation{ConversationID: convID, ParticipantLo: lo, ParticipantHi: hi, CreatedAtUnix: 500})

	store.deleteConversationRecord(convID)
	if _, ok := store.getConversation(convID); ok {
		t.Fatal("expected the conversation to be gone after deleteConversationRecord")
	}

	// A retry for the same pair afterward must be able to insert cleanly
	// (proves the unique index slot was actually freed, not merely the row
	// hidden).
	newID := "conv-retry-" + run
	t.Cleanup(func() { cleanupConversation(t, store, newID) })
	rec, created := store.findOrCreateConversation(Conversation{ConversationID: newID, ParticipantLo: lo, ParticipantHi: hi, CreatedAtUnix: 999})
	if !created || rec.ConversationID != newID {
		t.Fatalf("expected a fresh insert to succeed after delete, got created=%v rec=%+v", created, rec)
	}
}

// TestPostgresStore_MessagesSeqOrderAndPagination covers addMessage/
// listMessages'/messageSeq's seq-ordering and cursor-pagination guarantees.
func TestPostgresStore_MessagesSeqOrderAndPagination(t *testing.T) {
	store := newTestPostgresStore(t)
	run := uniqueRunID(t)
	convID := "conv-" + run
	lo, hi := "identity:alice-"+run, "identity:bob-"+run
	store.findOrCreateConversation(Conversation{ConversationID: convID, ParticipantLo: lo, ParticipantHi: hi, CreatedAtUnix: 500})
	t.Cleanup(func() { cleanupConversation(t, store, convID) })

	ids := make([]string, 0, 5)
	for i := 0; i < 5; i++ {
		id := "msg-" + run + "-" + string(rune('a'+i))
		store.addMessage(Message{
			MessageID: id, ConversationID: convID, Sender: lo,
			Ciphertext: []byte("ct"), SentAtUnix: int64(100 + i),
		})
		ids = append(ids, id)
	}

	// Default (no cursor): most recent 3, ascending.
	page1, hasMore1 := store.listMessages(convID, nil, 3)
	if len(page1) != 3 || !hasMore1 {
		t.Fatalf("expected 3 messages with hasMore=true, got %d messages hasMore=%v", len(page1), hasMore1)
	}
	if page1[0].MessageID != ids[2] || page1[1].MessageID != ids[3] || page1[2].MessageID != ids[4] {
		t.Fatalf("expected the last 3 messages ascending, got %v", []string{page1[0].MessageID, page1[1].MessageID, page1[2].MessageID})
	}

	seq, found := store.messageSeq(convID, page1[0].MessageID)
	if !found {
		t.Fatal("expected messageSeq to resolve the first page's first message_id")
	}
	page2, hasMore2 := store.listMessages(convID, &seq, 10)
	if hasMore2 {
		t.Fatal("expected no further messages beyond the remaining 2")
	}
	if len(page2) != 2 || page2[0].MessageID != ids[0] || page2[1].MessageID != ids[1] {
		t.Fatalf("expected the first 2 messages ascending, got %+v", page2)
	}

	if _, found := store.messageSeq(convID, "msg-does-not-exist"); found {
		t.Fatal("expected a miss for a message_id that was never added")
	}
}

func TestPostgresStore_AllMessagesForConversation(t *testing.T) {
	store := newTestPostgresStore(t)
	run := uniqueRunID(t)
	convID := "conv-" + run
	lo, hi := "identity:alice-"+run, "identity:bob-"+run
	store.findOrCreateConversation(Conversation{ConversationID: convID, ParticipantLo: lo, ParticipantHi: hi, CreatedAtUnix: 500})
	t.Cleanup(func() { cleanupConversation(t, store, convID) })

	for i := 0; i < 3; i++ {
		store.addMessage(Message{
			MessageID: "msg-" + run + "-" + string(rune('a'+i)), ConversationID: convID, Sender: lo,
			Ciphertext: []byte("ct"), SessionEstablishmentPayload: []byte("payload"), SentAtUnix: int64(100 + i),
		})
	}

	all := store.allMessagesForConversation(convID)
	if len(all) != 3 {
		t.Fatalf("expected all 3 messages, got %d", len(all))
	}
	for _, m := range all {
		if string(m.SessionEstablishmentPayload) != "payload" {
			t.Fatalf("expected session_establishment_payload to round-trip, got %q", m.SessionEstablishmentPayload)
		}
	}
}

// TestPostgresStore_ConversationSummariesForSubject_OmitsZeroMessage covers
// the query-shape requirement: a conversation with zero messages must not
// appear in conversationSummariesForSubject's result at all (charter §3/§4).
func TestPostgresStore_ConversationSummariesForSubject_OmitsZeroMessage(t *testing.T) {
	store := newTestPostgresStore(t)
	run := uniqueRunID(t)
	emptyConvID := "conv-empty-" + run
	populatedConvID := "conv-populated-" + run
	lo := "identity:alice-" + run
	hi1 := "identity:bob-" + run
	hi2 := "identity:carol-" + run

	store.findOrCreateConversation(Conversation{ConversationID: emptyConvID, ParticipantLo: lo, ParticipantHi: hi1, CreatedAtUnix: 500})
	t.Cleanup(func() { cleanupConversation(t, store, emptyConvID) })
	store.findOrCreateConversation(Conversation{ConversationID: populatedConvID, ParticipantLo: lo, ParticipantHi: hi2, CreatedAtUnix: 600})
	t.Cleanup(func() { cleanupConversation(t, store, populatedConvID) })
	store.addMessage(Message{MessageID: "msg-" + run, ConversationID: populatedConvID, Sender: lo, Ciphertext: []byte("ct"), SentAtUnix: 700})

	summaries := store.conversationSummariesForSubject(lo)
	if len(summaries) != 1 {
		t.Fatalf("expected exactly 1 summary (the populated conversation), got %d: %+v", len(summaries), summaries)
	}
	got := summaries[0]
	if got.ConversationID != populatedConvID {
		t.Fatalf("expected the populated conversation, got %q", got.ConversationID)
	}
	if got.OtherParticipant != hi2 {
		t.Fatalf("expected other_participant=%q, got %q", hi2, got.OtherParticipant)
	}
	if got.LastMessageAtUnix != 700 {
		t.Fatalf("expected last_message_at_unix=700 (derived from the message), got %d", got.LastMessageAtUnix)
	}
}
