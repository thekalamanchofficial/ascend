// Regression coverage for the Security Steward implementation-merge-gate
// veto, 2026-08-25 (see docs/DECISION_LOG.md, "Conversations mobile client
// implementation merge gate: Security Steward vetoes an unprotected
// concurrent read-modify-write race in local session/history storage").
//
// Both `localStore.ts`'s session-handle map and `history.ts`'s `appendRows`
// used to do a `secureLocalRetrieve` -> mutate-in-JS -> `secureLocalStore`
// sequence with a real `await` boundary and NO locking — exactly the hazard
// class `capabilities/crypto/prekeyStore.ts`'s `withOneTimePrekeyLock` and
// `capabilities/crypto/keyRegistry.ts`'s `withRatchetSessionLock` already
// exist to close elsewhere in this codebase. These tests mirror
// `crypto.test.ts`'s own "REAL CONCURRENCY" test structure exactly: fire
// every call via `Promise.all` with NO `await` in between, so the actual
// race window a mutex exists to close is genuinely exercised (via the real
// `secureLocalStore`/`secureLocalRetrieve` async boundary, backed by the
// automatically-applied `expo-secure-store` Jest manual mock) — not a
// simulated, false-negative-prone sequential test.
import { getCachedSessionHandle, setCachedSessionHandle } from "../localStore";
import { appendRows, loadHistory } from "../history";
import { _resetConversationsLocksForTests } from "../mutex";
import type { LocalMessageRow } from "../history";

beforeEach(() => {
  _resetConversationsLocksForTests();
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const secureStoreMock = require("expo-secure-store");
  if (typeof secureStoreMock.__reset === "function") secureStoreMock.__reset();
});

describe("localStore.ts — session-handle map, concurrent writes", () => {
  it("REAL CONCURRENCY: concurrent setCachedSessionHandle calls for DIFFERENT conversations don't lose updates (the exact race the veto traced: an in-flight background sync racing a foreground send)", async () => {
    const conversationCount = 6;
    const conversationIds = Array.from({ length: conversationCount }, (_, i) => `conv-${i}`);

    // All fired without awaiting in between — the actual race window the
    // mutex exists to close, not a simulated one. Every call reads +
    // rewrites the SAME shared session-map blob.
    await Promise.all(
      conversationIds.map((id, i) => setCachedSessionHandle(id, { handle: `ratchet_${i}` })),
    );

    // A lost update (two concurrent calls both reading the same
    // not-yet-updated blob, one clobbering the other's persisted result)
    // would leave some of these missing.
    const results = await Promise.all(conversationIds.map((id) => getCachedSessionHandle(id)));
    for (let i = 0; i < conversationCount; i++) {
      expect(results[i]).toEqual({ handle: `ratchet_${i}` });
    }
  });

  it("a LATER concurrent write for an already-cached conversation doesn't erase a DIFFERENT, already-cached conversation's entry", async () => {
    // Seed one entry first (sequential — establishing the pre-existing state).
    await setCachedSessionHandle("conv-existing", { handle: "ratchet_existing" });

    // Now race a write to a NEW conversation against a few more concurrent
    // writes, all sharing the same underlying blob as "conv-existing".
    await Promise.all([
      setCachedSessionHandle("conv-new-1", { handle: "ratchet_new_1" }),
      setCachedSessionHandle("conv-new-2", { handle: "ratchet_new_2" }),
      setCachedSessionHandle("conv-new-3", { handle: "ratchet_new_3" }),
    ]);

    expect(await getCachedSessionHandle("conv-existing")).toEqual({ handle: "ratchet_existing" });
    expect(await getCachedSessionHandle("conv-new-1")).toEqual({ handle: "ratchet_new_1" });
    expect(await getCachedSessionHandle("conv-new-2")).toEqual({ handle: "ratchet_new_2" });
    expect(await getCachedSessionHandle("conv-new-3")).toEqual({ handle: "ratchet_new_3" });
  });
});

describe("history.ts — appendRows, concurrent writes to the SAME conversation", () => {
  function row(messageId: string, sentAtUnix: number): LocalMessageRow {
    return { messageId, sender: "identity-someone", sentAtUnix, direction: "received", plaintext: `text-${messageId}`, undecryptable: false };
  }

  it("REAL CONCURRENCY: concurrent appendRows calls for the SAME conversationId don't lose rows (the exact race the veto traced — a background sync's append racing a foreground send's append)", async () => {
    const conversationId = "conv-shared";
    const rowCount = 6;
    const rows = Array.from({ length: rowCount }, (_, i) => row(`msg-${i}`, 1000 + i));

    // Each concurrent call appends exactly ONE new row — simulating several
    // independent writers (e.g. a just-completed send, and a background
    // history sync that just finished decrypting an incoming message)
    // racing the same underlying per-conversation blob.
    await Promise.all(rows.map((r) => appendRows(conversationId, [r])));

    const finalHistory = await loadHistory(conversationId);
    expect(finalHistory).toHaveLength(rowCount);
    const finalIds = new Set(finalHistory.map((r) => r.messageId));
    for (const r of rows) {
      expect(finalIds.has(r.messageId)).toBe(true);
    }
  });

  it("concurrent appendRows calls for DIFFERENT conversations do not interfere with each other (the lock is per-conversationId, not global)", async () => {
    await Promise.all([
      appendRows("conv-a", [row("a-1", 1)]),
      appendRows("conv-b", [row("b-1", 1)]),
      appendRows("conv-a", [row("a-2", 2)]),
      appendRows("conv-b", [row("b-2", 2)]),
    ]);

    const historyA = await loadHistory("conv-a");
    const historyB = await loadHistory("conv-b");
    expect(historyA.map((r) => r.messageId).sort()).toEqual(["a-1", "a-2"]);
    expect(historyB.map((r) => r.messageId).sort()).toEqual(["b-1", "b-2"]);
  });

  it("a duplicate messageId delivered concurrently with a genuinely new row is deduped, never double-counted", async () => {
    const conversationId = "conv-dedupe";
    await appendRows(conversationId, [row("msg-existing", 500)]);

    await Promise.all([
      appendRows(conversationId, [row("msg-existing", 500)]), // duplicate
      appendRows(conversationId, [row("msg-new", 501)]),
    ]);

    const finalHistory = await loadHistory(conversationId);
    expect(finalHistory.map((r) => r.messageId).sort()).toEqual(["msg-existing", "msg-new"]);
  });
});
