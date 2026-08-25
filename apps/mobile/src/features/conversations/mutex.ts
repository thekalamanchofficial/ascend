// Per-key in-process mutex — the identical `Map<string, Promise<void>>`
// pattern already established twice in this codebase for exactly this
// hazard class (`capabilities/crypto/prekeyStore.ts`'s
// `withOneTimePrekeyLock`, `capabilities/crypto/keyRegistry.ts`'s
// `withRatchetSessionLock`), factored out here rather than a third
// hand-copied implementation, since `localStore.ts` and `history.ts` both
// need it (Security Steward implementation-merge-gate veto, 2026-08-25 —
// see docs/DECISION_LOG.md: an unprotected `secureLocalRetrieve` ->
// mutate-in-JS -> `secureLocalStore` read-modify-write sequence, with real
// `await` boundaries and no locking, is a genuine concurrent-write race —
// two concretely reachable triggers were traced: the compose screen's Send
// button not being disabled during an in-flight background
// `syncThreadHistory`, and navigating away mid-sync not cancelling the
// in-flight promise chain). React Native's single-threaded JS execution
// makes an in-process `Promise`-based lock sufficient — no OS-level locking
// required, identical reasoning already established at both prior call
// sites.
const locks = new Map<string, Promise<void>>();

/**
 * Serializes concurrent calls sharing the same `key` — the second (and
 * every subsequent) concurrent caller for the same `key` waits for the
 * prior one to fully finish (including its own store write) before its own
 * `fn` runs, closing the exact "both read the same not-yet-updated blob,
 * both write, second write silently clobbers the first" race this exists
 * to prevent. Calls for DIFFERENT keys never block each other.
 */
export async function withKeyLock<T>(key: string, fn: () => Promise<T>): Promise<T> {
  const prior = locks.get(key) ?? Promise.resolve();
  let release!: () => void;
  const mine = new Promise<void>((resolve) => {
    release = resolve;
  });
  // Publish `mine` as the new lock slot BEFORE awaiting `prior`, so a
  // concurrent caller arriving between now and when we finish sees `mine`
  // (not `prior`) as what it must wait on — this is what actually
  // serializes the calls rather than letting them all read `prior` and all
  // proceed once it resolves. Identical structure to
  // `prekeyStore.ts`'s `withOneTimePrekeyLock`/`keyRegistry.ts`'s
  // `withRatchetSessionLock` — see either's own comment for the full
  // TOCTOU-avoidance rationale.
  locks.set(key, mine);
  await prior;
  try {
    return await fn();
  } finally {
    release();
    // Clean up only if nobody chained after us, to avoid unbounded map growth.
    if (locks.get(key) === mine) {
      locks.delete(key);
    }
  }
}

/** Test-only: clears in-process lock state between test cases. */
export function _resetConversationsLocksForTests(): void {
  locks.clear();
}
