-- Reverses 0011_conversations.up.sql. Does not DROP ROLE ascend_app: that
-- role is owned by migration 0001 and may still be depended on by other
-- tables' grants — dropping it here would break, not help, a rollback.
REVOKE ALL ON messages FROM ascend_app;
REVOKE ALL ON conversations FROM ascend_app;

DROP INDEX IF EXISTS idx_messages_conversation_seq;
DROP TABLE IF EXISTS messages;

DROP INDEX IF EXISTS idx_conversations_participant_hi;
DROP INDEX IF EXISTS idx_conversations_participant_lo;
DROP INDEX IF EXISTS idx_conversations_pair;
DROP TABLE IF EXISTS conversations;
