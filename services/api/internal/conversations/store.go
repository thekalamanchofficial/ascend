package conversations

import "sync"

// Store is the persistence boundary this package's Service depends on. It
// is intentionally narrow and storage-agnostic — InMemoryStore below is a
// mutex-guarded, process-lifetime implementation; PostgresStore
// (postgres_store.go) is a real Postgres-backed implementation of the exact
// same interface, so Service (service.go) is written against Store and does
// not know or care which implementation actually backs it. Mirrors
// fileobjects.Store's identical design (internal/fileobjects/store.go).
type Store interface {
	// findOrCreateConversation is CreateConversation's single atomic
	// primitive (charter §3's idempotent-by-pair requirement). candidate
	// must already carry a canonical pair (ParticipantLo <= ParticipantHi
	// lexicographically — see canonicalPair in service.go) and a freshly
	// generated ConversationID. If no row exists yet for candidate's pair,
	// candidate is inserted and returned with created=true. If a row
	// already exists for that pair, THAT row is returned unchanged, with
	// created=false — candidate's own ConversationID is discarded. This
	// must never be implemented as a separate exists-check followed by a
	// separate insert (race-prone); see postgres_store.go's single-
	// statement implementation for why.
	findOrCreateConversation(candidate Conversation) (rec Conversation, created bool)

	getConversation(conversationID string) (Conversation, bool)

	// deleteConversationRecord is ROLLBACK-ONLY plumbing for
	// CreateConversation's own failure path (service.go) — there is no
	// public DeleteConversation RPC in this charter's freeze. Because a
	// brand-new conversation_id is generated fresh (crypto/rand) on every
	// CreateConversation attempt, rolling back here only ever removes a
	// row this exact call just inserted, before returning its ID to any
	// caller — never a conversation any other RPC could have already
	// referenced.
	deleteConversationRecord(conversationID string)

	addMessage(m Message)

	// messageSeq resolves messageID (which must belong to conversationID)
	// to its internal ordering sequence number — backing ListMessages'
	// before_message_id cursor (charter §3). found=false if messageID
	// doesn't exist, or exists but belongs to a different conversation.
	messageSeq(conversationID, messageID string) (seq int64, found bool)

	// listMessages returns up to limit messages for conversationID in
	// ascending chronological (seq) order. With beforeSeq == nil, returns
	// the MOST RECENT page (the last `limit` messages), still ascending —
	// matching the proto's "omit to start from the most recent page"
	// comment. With beforeSeq != nil, returns the `limit` messages
	// immediately preceding (strictly less than) that sequence number,
	// again ascending. hasMore reports whether at least one further
	// (older) message exists beyond what was returned — i.e. whether a
	// follow-up call with before_message_id set to the returned page's
	// first message would return anything.
	listMessages(conversationID string, beforeSeq *int64, limit int) (messages []Message, hasMore bool)

	// allMessagesForConversation returns EVERY message for conversationID,
	// ascending, unpaginated — backing ExportConversation's "complete
	// artifact" bar (charter §3/§4 Art. 9), never used by ListMessages.
	allMessagesForConversation(conversationID string) []Message

	// conversationSummariesForSubject returns one ConversationSummary per
	// conversation subject participates in that has AT LEAST ONE message —
	// a conversation with zero messages (the CreateConversation-succeeded/
	// SendMessage-failed partial-failure gap, charter §3/§5) is omitted
	// entirely, a QUERY-SHAPE requirement (see postgres_store.go's INNER
	// JOIN), not a post-filter applied after the fact. LastMessageAtUnix on
	// each summary is MAX(sent_at_unix) computed here, at query time, never
	// persisted (charter §3/§4 Art. 8).
	conversationSummariesForSubject(subject string) []ConversationSummary
}

// InMemoryStore is the first-pass Store implementation: a mutex-guarded,
// process-lifetime store — same precedent as every other capability's own
// first-wave in-memory store in this build. See docs/DECISION_LOG.md.
type InMemoryStore struct {
	mu sync.RWMutex

	conversations map[string]Conversation
	// pairIndex maps a canonical pair key (pairKey(lo, hi)) to the
	// conversation_id currently backing it — the in-memory equivalent of
	// PostgresStore's UNIQUE (participant_lo, participant_hi) index.
	pairIndex map[string]string
	// messages holds every message per conversation, in seq (append)
	// order — never reordered or pruned (no DeleteMessage exists).
	messages map[string][]Message
	nextSeq  int64
}

// newInMemoryStore is unexported, mirroring fileobjects.newInMemoryStore —
// this package's only "swap the Store implementation" seam is NewService's
// store parameter (service.go), never a package-level constructor a caller
// outside this package would reach for.
func newInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		conversations: make(map[string]Conversation),
		pairIndex:     make(map[string]string),
		messages:      make(map[string][]Message),
	}
}

func pairKey(lo, hi string) string { return lo + "\x1f" + hi }

func (s *InMemoryStore) findOrCreateConversation(candidate Conversation) (Conversation, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := pairKey(candidate.ParticipantLo, candidate.ParticipantHi)
	if existingID, ok := s.pairIndex[key]; ok {
		return s.conversations[existingID], false
	}
	s.pairIndex[key] = candidate.ConversationID
	s.conversations[candidate.ConversationID] = candidate
	return candidate, true
}

func (s *InMemoryStore) getConversation(id string) (Conversation, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.conversations[id]
	return c, ok
}

func (s *InMemoryStore) deleteConversationRecord(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.conversations[id]
	if !ok {
		return
	}
	delete(s.conversations, id)
	delete(s.pairIndex, pairKey(rec.ParticipantLo, rec.ParticipantHi))
	delete(s.messages, id)
}

func (s *InMemoryStore) addMessage(m Message) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextSeq++
	m.Seq = s.nextSeq
	s.messages[m.ConversationID] = append(s.messages[m.ConversationID], m)
}

func (s *InMemoryStore) messageSeq(conversationID, messageID string) (int64, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, m := range s.messages[conversationID] {
		if m.MessageID == messageID {
			return m.Seq, true
		}
	}
	return 0, false
}

// listMessages implements the "most-recent-page-by-default,
// page-before-cursor-otherwise, always ascending" semantics documented on
// the Store interface above.
func (s *InMemoryStore) listMessages(conversationID string, beforeSeq *int64, limit int) ([]Message, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	all := s.messages[conversationID] // already ascending by seq (append order)
	var eligible []Message
	if beforeSeq == nil {
		eligible = all
	} else {
		for _, m := range all {
			if m.Seq < *beforeSeq {
				eligible = append(eligible, m)
			}
		}
	}

	hasMore := false
	start := 0
	if len(eligible) > limit {
		hasMore = true
		start = len(eligible) - limit
	}
	page := append([]Message(nil), eligible[start:]...)
	return page, hasMore
}

func (s *InMemoryStore) allMessagesForConversation(conversationID string) []Message {
	s.mu.RLock()
	defer s.mu.RUnlock()
	src := s.messages[conversationID]
	out := make([]Message, len(src))
	copy(out, src)
	return out
}

func (s *InMemoryStore) conversationSummariesForSubject(subject string) []ConversationSummary {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]ConversationSummary, 0)
	for id, c := range s.conversations {
		if c.ParticipantLo != subject && c.ParticipantHi != subject {
			continue
		}
		msgs := s.messages[id]
		if len(msgs) == 0 {
			continue // omit entirely — see the interface doc comment above
		}
		var lastMessageAt int64
		for _, m := range msgs {
			if m.SentAtUnix > lastMessageAt {
				lastMessageAt = m.SentAtUnix
			}
		}
		other := c.ParticipantHi
		if c.ParticipantHi == subject {
			other = c.ParticipantLo
		}
		out = append(out, ConversationSummary{
			ConversationID:    id,
			OtherParticipant:  other,
			CreatedAtUnix:     c.CreatedAtUnix,
			LastMessageAtUnix: lastMessageAt,
		})
	}
	return out
}
