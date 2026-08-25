// Prekey bundle lifecycle — cryptography-and-keys.charter.md §3/§5: "fully
// invisible, automatic background maintenance — no user action, no user
// awareness required for the common case." No dedicated screen exists for
// this anywhere in this app, by design.
//
// TIMING DECISION (named per this pass's brief — "on identity creation/
// restoration, or lazily, the first time Conversations is opened, whichever
// is simpler to implement correctly — your call, name the choice"):
// implemented LAZILY, on first Conversations-surface open
// (ConversationsListScreen / StartConversationScreen's mount), NOT wired
// into onboarding.ts's createIdentityFlow/restoreIdentityFlow. Reasoning:
// onboarding.ts already carries a real, disclosed limitation (no persistent
// login across a cold restart — see that file's own "KNOWN GAP" comment) and
// crypto.generatePrekeyBundle requires the identity's private key to already
// be registered THIS PROCESS (keyRegistry.findPrivateKeyEntryByPurpose) —
// exactly the same "only works for as long as this process is alive"
// constraint onboarding.ts's own session-renewal machinery already lives
// with. Doing it lazily, gated by ensureOwnPrekeyIdentity's own local cache
// (below), means it fires exactly once per device's real lifetime (not once
// per onboarding flow AND once per Conversations open), and never adds a
// third failure-prone network call to the already-multi-step create/restore
// journeys — Conversations is the only capability that needs this
// machinery, so it is the one that owns triggering it. Rotation/replenishment
// cadence beyond this one-time bootstrap is explicitly out of scope for this
// pass (charter §3: "exact cadence/thresholds are an implementation
// decision... not charter-mandated") — named as a follow-up in this pass's
// report, not built here.
import * as crypto from "../../capabilities/crypto";
import * as identity from "../../capabilities/identity";
import { loadOwnPrekeyIdentity, saveOwnPrekeyIdentity } from "./localStore";

const ONE_TIME_PREKEY_COUNT = 20;

export interface OwnPrekeyIdentity {
  identityDhPublicKey: Uint8Array;
  identityDhPublicKeySignature: Uint8Array;
}

/**
 * Idempotent: if this device has already generated+published its prekey
 * bundle (checked via the local cache, never by re-fetching from the
 * server), this is a same-process no-op that returns the cached value with
 * no network calls at all. Only the FIRST call for a given deviceId in this
 * device's lifetime actually calls crypto.generatePrekeyBundle +
 * identity.publishPrekeyBundle.
 */
export async function ensureOwnPrekeyIdentity(params: {
  identityRef: string;
  deviceId: string;
  sessionToken: string;
}): Promise<OwnPrekeyIdentity> {
  const cached = await loadOwnPrekeyIdentity(params.deviceId);
  if (cached) return cached;

  const bundle = await crypto.generatePrekeyBundle({ oneTimePrekeyCount: ONE_TIME_PREKEY_COUNT });

  await identity.publishPrekeyBundle(
    {
      identityRef: params.identityRef,
      deviceId: params.deviceId,
      signedPrekey: bundle.signedPrekey,
      oneTimePrekeys: bundle.oneTimePrekeys,
      identityDhPublicKey: bundle.identityDhPublicKey,
      identityDhPublicKeySignature: bundle.identityDhPublicKeySignature,
    },
    params.sessionToken,
  );

  const value: OwnPrekeyIdentity = {
    identityDhPublicKey: bundle.identityDhPublicKey,
    identityDhPublicKeySignature: bundle.identityDhPublicKeySignature,
  };
  await saveOwnPrekeyIdentity(params.deviceId, value);
  return value;
}
