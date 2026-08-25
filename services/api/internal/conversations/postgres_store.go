package conversations

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresStore is a Postgres-backed implementation of Store, persisting
// Conversation/Message rows into the conversations/messages tables (see
// internal/platform/migrations/0011_conversations.up.sql). Service
// (service.go) is written against the Store interface and does not know or
// care which implementation actually backs it — mirrors
// fileobjects.PostgresStore's identical design
// (internal/fileobjects/postgres_store.go), including its error-handling
// split below.
//
// # Error-handling design decision (same split fileobjects.PostgresStore uses)
//
// Store's methods split into two groups: read methods (getConversation,
// messageSeq, listMessages, allMessagesForConversation,
// conversationSummariesForSubject) fold a genuine query failure into the
// same shape as a legitimate miss/empty-result — every caller in
// service.go already treats a miss as "not found"/"nothing to show", never
// as an implicit allow. Mutation methods with no error-return channel
// (addMessage, deleteConversationRecord) panic on a genuine failure via
// storeFailure, identical in spirit and mechanism to
// fileobjects.PostgresStore's own storeFailure — a panic inside an HTTP
// handler goroutine is recovered per-request by Go's net/http server (logs
// the stack trace, closes that one connection), a hard, visible failure,
// never a silent 200-with-lies response.
//
// findOrCreateConversation is the one exception to "reads fold failure into
// a legitimate-looking result": a genuine failure there also panics via
// storeFailure, because folding it into "not created, use whatever's in the
// row" would risk returning a zero-value Conversation as if it were a real
// existing row — the same "never silently pretend a mutation-adjacent
// operation succeeded" reasoning as the pure-mutation methods, applied here
// because this method both reads AND conditionally writes in one
// statement.
type PostgresStore struct {
	pool *pgxpool.Pool
}

// NewPostgresStore constructs a PostgresStore against an already-connected
// pool. Callers are responsible for having already run this package's
// migration (0011_conversations.up.sql) against the same database — this
// constructor does not run migrations itself (that is platform.New's job,
// at server startup).
func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

func storeFailure(op string, err error) {
	panic(fmt.Sprintf("conversations: postgres %s: %v", op, err))
}

// findOrCreateConversation is CreateConversation's single atomic primitive
// (charter §3's idempotent-by-pair requirement), expressed as ONE SQL
// statement — never a separate exists-check followed by a separate insert.
// The `ins` CTE attempts the insert; `ON CONFLICT (participant_lo,
// participant_hi) DO NOTHING` makes it a no-op (not an error) if the pair
// already has a row. The outer UNION ALL then returns either the row `ins`
// just inserted (created=true) or, only if `ins` produced nothing, the
// pair's pre-existing row (created=false) — `NOT EXISTS (SELECT 1 FROM
// ins)` is what makes these two branches mutually exclusive, so exactly one
// row comes back either way. Because this is a single statement, Postgres
// wraps it in an implicit transaction; under real concurrent execution, one
// of two racing callers' INSERT succeeds and the other's blocks briefly on
// the unique index before seeing the conflict and falling through to the
// SELECT branch — there is no window in which both branches could return
// created=true for the same pair, nor one in which either sees a
// half-committed row. See docs/DECISION_LOG.md, "Conversations:
// CreateConversation's atomic find-or-create query", for the full
// concurrency reasoning and why this was chosen over identity's own
// SELECT...FOR UPDATE SKIP LOCKED precedent (a different shape, for a
// different problem — claiming one of many interchangeable rows, not
// deciding whether a single canonical row already exists).
func (s *PostgresStore) findOrCreateConversation(candidate Conversation) (Conversation, bool) {
	ctx := context.Background()
	row := s.pool.QueryRow(ctx, `
		WITH ins AS (
			INSERT INTO conversations (conversation_id, participant_lo, participant_hi, created_at_unix)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (participant_lo, participant_hi) DO NOTHING
			RETURNING conversation_id, participant_lo, participant_hi, created_at_unix
		)
		SELECT conversation_id, participant_lo, participant_hi, created_at_unix, TRUE AS created
		FROM ins
		UNION ALL
		SELECT conversation_id, participant_lo, participant_hi, created_at_unix, FALSE AS created
		FROM conversations
		WHERE participant_lo = $2 AND participant_hi = $3
		  AND NOT EXISTS (SELECT 1 FROM ins)
	`, candidate.ConversationID, candidate.ParticipantLo, candidate.ParticipantHi, candidate.CreatedAtUnix)

	var rec Conversation
	var created bool
	if err := row.Scan(&rec.ConversationID, &rec.ParticipantLo, &rec.ParticipantHi, &rec.CreatedAtUnix, &created); err != nil {
		storeFailure("find_or_create_conversation", err)
	}
	return rec, created
}

func (s *PostgresStore) getConversation(id string) (Conversation, bool) {
	ctx := context.Background()
	row := s.pool.QueryRow(ctx, `
		SELECT conversation_id, participant_lo, participant_hi, created_at_unix
		FROM conversations
		WHERE conversation_id = $1
	`, id)

	var rec Conversation
	if err := row.Scan(&rec.ConversationID, &rec.ParticipantLo, &rec.ParticipantHi, &rec.CreatedAtUnix); err != nil {
		return Conversation{}, false
	}
	return rec, true
}

// deleteConversationRecord is CreateConversation's own rollback-only
// plumbing (see the Store interface's doc comment) — a genuine failure here
// panics rather than silently leaving a partially-bootstrapped, now-
// unreachable-but-not-actually-deleted row behind.
func (s *PostgresStore) deleteConversationRecord(id string) {
	ctx := context.Background()
	if _, err := s.pool.Exec(ctx, `DELETE FROM conversations WHERE conversation_id = $1`, id); err != nil {
		storeFailure("delete_conversation_record", err)
	}
}

func (s *PostgresStore) addMessage(m Message) {
	ctx := context.Background()
	_, err := s.pool.Exec(ctx, `
		INSERT INTO messages
			(message_id, conversation_id, sender, ciphertext, session_establishment_payload, sent_at_unix)
		VALUES
			($1, $2, $3, $4, $5, $6)
	`, m.MessageID, m.ConversationID, m.Sender, m.Ciphertext, m.SessionEstablishmentPayload, m.SentAtUnix)
	if err != nil {
		storeFailure("add_message", err)
	}
}

func (s *PostgresStore) messageSeq(conversationID, messageID string) (int64, bool) {
	ctx := context.Background()
	var seq int64
	err := s.pool.QueryRow(ctx, `
		SELECT seq FROM messages WHERE conversation_id = $1 AND message_id = $2
	`, conversationID, messageID).Scan(&seq)
	if err != nil {
		return 0, false
	}
	return seq, true
}

// listMessages fetches limit+1 rows (newest-first) so it can tell whether a
// further, older page exists (hasMore) without a separate COUNT query, then
// trims the extra row and reverses into ascending order — see the Store
// interface's doc comment for the exact semantics this implements.
func (s *PostgresStore) listMessages(conversationID string, beforeSeq *int64, limit int) ([]Message, bool) {
	ctx := context.Background()

	var rows pgx.Rows
	var err error
	if beforeSeq != nil {
		rows, err = s.pool.Query(ctx, `
			SELECT message_id, conversation_id, sender, ciphertext, session_establishment_payload, sent_at_unix, seq
			FROM messages
			WHERE conversation_id = $1 AND seq < $2
			ORDER BY seq DESC
			LIMIT $3
		`, conversationID, *beforeSeq, limit+1)
	} else {
		rows, err = s.pool.Query(ctx, `
			SELECT message_id, conversation_id, sender, ciphertext, session_establishment_payload, sent_at_unix, seq
			FROM messages
			WHERE conversation_id = $1
			ORDER BY seq DESC
			LIMIT $2
		`, conversationID, limit+1)
	}
	if err != nil {
		return []Message{}, false
	}
	defer rows.Close()

	desc := make([]Message, 0, limit+1)
	for rows.Next() {
		m, err := scanMessage(rows)
		if err != nil {
			return []Message{}, false
		}
		desc = append(desc, m)
	}
	if rows.Err() != nil {
		return []Message{}, false
	}

	hasMore := false
	if len(desc) > limit {
		hasMore = true
		desc = desc[:limit]
	}

	out := make([]Message, len(desc))
	for i, m := range desc {
		out[len(desc)-1-i] = m // reverse: desc is newest-first, out must be ascending
	}
	return out, hasMore
}

func (s *PostgresStore) allMessagesForConversation(conversationID string) []Message {
	ctx := context.Background()
	rows, err := s.pool.Query(ctx, `
		SELECT message_id, conversation_id, sender, ciphertext, session_establishment_payload, sent_at_unix, seq
		FROM messages
		WHERE conversation_id = $1
		ORDER BY seq ASC
	`, conversationID)
	if err != nil {
		return []Message{}
	}
	defer rows.Close()

	out := make([]Message, 0)
	for rows.Next() {
		m, err := scanMessage(rows)
		if err != nil {
			return []Message{}
		}
		out = append(out, m)
	}
	if rows.Err() != nil {
		return []Message{}
	}
	return out
}

// conversationSummariesForSubject's INNER JOIN is what makes "a conversation
// with zero messages is omitted entirely" a query-shape guarantee (charter
// §3/§4) rather than a post-filter applied in Go after the fact — a
// conversation row with no matching messages row simply never appears in
// the join's result set at all. MAX(sent_at_unix) is computed here, at
// query time, per charter §3/§4 Art. 8 — this column does not exist
// anywhere in the conversations table.
func (s *PostgresStore) conversationSummariesForSubject(subject string) []ConversationSummary {
	ctx := context.Background()
	rows, err := s.pool.Query(ctx, `
		SELECT c.conversation_id,
		       CASE WHEN c.participant_lo = $1 THEN c.participant_hi ELSE c.participant_lo END AS other_participant,
		       c.created_at_unix,
		       MAX(m.sent_at_unix) AS last_message_at_unix
		FROM conversations c
		INNER JOIN messages m ON m.conversation_id = c.conversation_id
		WHERE c.participant_lo = $1 OR c.participant_hi = $1
		GROUP BY c.conversation_id, c.participant_lo, c.participant_hi, c.created_at_unix
	`, subject)
	if err != nil {
		return []ConversationSummary{}
	}
	defer rows.Close()

	out := make([]ConversationSummary, 0)
	for rows.Next() {
		var cs ConversationSummary
		if err := rows.Scan(&cs.ConversationID, &cs.OtherParticipant, &cs.CreatedAtUnix, &cs.LastMessageAtUnix); err != nil {
			return []ConversationSummary{}
		}
		out = append(out, cs)
	}
	if rows.Err() != nil {
		return []ConversationSummary{}
	}
	return out
}

// rowScanner is the common subset of pgx.Row and pgx.Rows this package
// needs (just Scan) — matches fileobjects.rowScanner's identical seam.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanMessage(row rowScanner) (Message, error) {
	var (
		m       Message
		payload []byte
	)
	err := row.Scan(&m.MessageID, &m.ConversationID, &m.Sender, &m.Ciphertext, &payload, &m.SentAtUnix, &m.Seq)
	if err != nil {
		return Message{}, err
	}
	m.SessionEstablishmentPayload = payload // nil if the column was NULL
	return m, nil
}
