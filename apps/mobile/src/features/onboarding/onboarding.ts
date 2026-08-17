// Onboarding — composition layer tying Cryptography & Keys, Identity, and
// Session/Request Authentication together into the two real user journeys
// Identity's charter §5 describes: creating a brand-new identity, and
// restoring one from a recovery phrase after total device loss. Per
// apps/mobile/README.md's capability boundary, this file contains no
// capability logic of its own — every actual decision (is this signature
// valid, is this device allowed to bind, is this session real) is made by
// the real backend services this module calls. This module only sequences
// those calls in the right order and keeps the small amount of local
// bookkeeping (identityRef/deviceId/epoch, the current session token) each
// journey needs.
//
// This is a feature composition, not a capability — see CLAUDE.md
// "Capabilities vs. features." It is intentionally NOT under
// apps/mobile/src/capabilities/, and its mutating functions are NOT
// subject to scripts/constitution/check-audit-events-ts.sh (that check is
// scoped to apps/mobile/src/capabilities/**, matching Cryptography &
// Keys' precedent). Every mutating step still calls the underlying
// capability client's own `// ascend:mutates`-marked function (which
// already logs its own client-side audit stub) and this module adds one
// more, coarser-grained audit line for the composed journey itself — see
// logAuditEvent calls below.
import * as crypto from "../../capabilities/crypto";
import * as identity from "../../capabilities/identity";
import * as sessionauth from "../../capabilities/sessionauth";
import { setAuthToken, ApiError } from "../../api/httpClient";
import { logAuditEvent } from "../../capabilities/identity/audit";
import { saveLocalIdentity, saveLocalSession, loadLocalIdentity, loadLocalSession } from "./localSession";
import type { LocalIdentityRecord, LocalSessionRecord } from "./localSession";

// Per-device signing key purpose — see
// apps/mobile/src/capabilities/crypto/keyPurpose.ts's own documented
// example ("a per-device signing key" -> "sign:device-binding"), reused
// here verbatim rather than inventing a new purpose string. Deliberately
// distinct from the identity root key's reserved "sign:identity" purpose
// (crypto/index.ts's IDENTITY_KEY_PURPOSE) — a device key and the identity
// root key are cryptographically and semantically different keys, per
// Identity's own device-binding model (services/api/internal/identity/sign.go's
// authorizesBinding checks the root key OR a bound device's key, never
// conflating the two).
const DEVICE_KEY_PURPOSE = "sign:device-binding";

export interface OnboardingResult {
  identityRef: string;
  deviceId: string;
  epoch: number;
  displayName: string;
  sessionToken: string;
  expiresAtUnix: number;
}

export interface CreateIdentityResult extends OnboardingResult {
  /**
   * Shown once, here, by this function's return value — never persisted,
   * never logged (see logAuditEvent calls below and
   * crypto/index.ts's generateIdentityKeyMaterial, which already refuses
   * to retain it). The caller (the create-identity screen) is responsible
   * for displaying it and requiring the user's active confirmation before
   * proceeding, per identity.charter.md §5.
   */
  recoveryPhrase: string;
}

// In-memory only — a KeyHandle is process-lifetime-scoped by construction
// (keyRegistry.ts: "intentionally volatile, cleared on process restart").
// Held here so a later automatic pre-expiry renewal (see
// scheduleSessionRenewal below) doesn't require every caller to replumb it.
//
// KNOWN GAP, flagged rather than worked around: Cryptography & Keys'
// frozen contract has no operation to reload a specific key's raw bytes
// back into a signable KeyHandle after a process restart (the one
// documented, deliberate exception to "private key material never leaves
// this module's boundary in plaintext" is ExportKeyMaterial, which is a
// full, explicit, user-confirmed export of every registered key at once —
// not a routine per-device reload primitive, and repeatedly auto-passing
// user_confirmation:true to avoid asking the user would defeat the point
// of that confirmation gate). Practically: automatic background session
// renewal (charter session-authentication.charter.md §5/§6) works
// correctly for as long as this app process stays alive, but a full
// process restart requires the user to go through the create/restore flow
// again to obtain a fresh device key — UNLESS a still-valid, previously
// issued sessionToken survives in SecureLocalStore (which it does — see
// loadLocalSession below), in which case the app can keep using that
// token until it naturally expires, just without the ability to renew it
// past expiry without a fresh signature. This is a real, structural gap in
// Cryptography & Keys' frozen contract, not an oversight in this module —
// routed back to the Chief Architect (see docs/DECISION_LOG.md, this
// pass's entry) rather than resolved by reaching into keyRegistry.ts's
// non-exported internals from outside the crypto module's own boundary.
let activeDeviceKeyHandle: crypto.KeyHandle | null = null;
let renewalTimer: ReturnType<typeof setTimeout> | null = null;

function clearScheduledRenewal(): void {
  if (renewalTimer !== null) {
    clearTimeout(renewalTimer);
    renewalTimer = null;
  }
}

// ---------------------------------------------------------------------------
// Shared session-bootstrap tail (charter session-authentication.charter.md
// §5: "session issuance is triggered automatically by the client
// immediately following a successful BindDevice... no user-visible step").
// ---------------------------------------------------------------------------
async function bootstrapSession(
  identityRef: string,
  deviceId: string,
  deviceKeyHandle: crypto.KeyHandle,
): Promise<LocalSessionRecord> {
  const challenge = await sessionauth.getSessionChallenge({ identityRef, deviceId });
  const message = sessionauth.buildIssueSessionMessage(identityRef, deviceId, challenge.challengeNonce);
  const { signature } = crypto.sign({ privateKeyHandle: deviceKeyHandle, message });
  const issued = await sessionauth.issueSession({
    identityRef,
    deviceId,
    challengeNonce: challenge.challengeNonce,
    proof: signature,
  });

  setAuthToken(issued.sessionToken);
  const record: LocalSessionRecord = { sessionToken: issued.sessionToken, expiresAtUnix: issued.expiresAtUnix };
  await saveLocalSession(record);

  activeDeviceKeyHandle = deviceKeyHandle;
  scheduleSessionRenewal(identityRef, deviceId, issued.expiresAtUnix);

  return record;
}

/**
 * Best-effort automatic renewal, well before expiresAtUnix, per charter
 * §6's "fresh-signature re-issuance, not bearer-token-only renewal"
 * commitment. Only works for as long as this process is alive and
 * activeDeviceKeyHandle is still the same one that was bound (see the
 * KNOWN GAP note above for the process-restart limitation). Renewal
 * failures are logged, not thrown — a background renewal failing must
 * never crash the app; the user simply falls back to needing to
 * re-authenticate once the current token naturally expires.
 */
function scheduleSessionRenewal(identityRef: string, deviceId: string, expiresAtUnix: number): void {
  clearScheduledRenewal();
  const nowMs = Date.now();
  const expiresAtMs = expiresAtUnix * 1000;
  // Renew at 80% of the remaining lifetime, floored at 5s so a very
  // short-lived token (e.g. in a test environment) doesn't schedule a
  // negative/immediate timer storm.
  const renewInMs = Math.max(5_000, Math.floor((expiresAtMs - nowMs) * 0.8));

  renewalTimer = setTimeout(() => {
    if (!activeDeviceKeyHandle) return;
    bootstrapSession(identityRef, deviceId, activeDeviceKeyHandle).catch((err) => {
      logAuditEvent("session_renewal_failed", { identityRef, deviceId, error: String(err) });
    });
  }, renewInMs);
}

// ---------------------------------------------------------------------------
// createIdentityFlow — identity.charter.md §5's zero-config path:
// generateIdentityKeyMaterial -> CreateIdentity -> store locally ->
// GetSessionChallenge -> sign -> IssueSession -> secureLocalStore.
// ---------------------------------------------------------------------------
export async function createIdentityFlow(request: {
  displayName: string;
  firstDeviceName: string;
}): Promise<CreateIdentityResult> {
  const identityKeyMaterial = crypto.generateIdentityKeyMaterial({});
  const deviceKeyPair = crypto.generateKeyPair({ purpose: DEVICE_KEY_PURPOSE });

  const created = await identity.createIdentity({
    displayName: request.displayName,
    publicKey: identityKeyMaterial.publicKey,
    firstDevicePublicKey: deviceKeyPair.publicKey,
    firstDeviceName: request.firstDeviceName,
  });

  const localRecord: LocalIdentityRecord = {
    identityRef: created.publicIdentity.identityRef,
    displayName: request.displayName,
    deviceId: created.firstDevice.deviceId,
    epoch: created.publicIdentity.epoch,
  };
  await saveLocalIdentity(localRecord);

  const session = await bootstrapSession(localRecord.identityRef, localRecord.deviceId, deviceKeyPair.privateKeyHandle);

  logAuditEvent("onboarding_identity_created", {
    identityRef: localRecord.identityRef,
    deviceId: localRecord.deviceId,
  });

  return {
    identityRef: localRecord.identityRef,
    deviceId: localRecord.deviceId,
    epoch: localRecord.epoch,
    displayName: localRecord.displayName,
    sessionToken: session.sessionToken,
    expiresAtUnix: session.expiresAtUnix,
    recoveryPhrase: identityKeyMaterial.recoveryPhrase,
  };
}

// ---------------------------------------------------------------------------
// restoreIdentityFlow — identity.charter.md §3/§7's "all devices lost"
// path: RestoreFromRecoveryPhrase re-derives the identity root key
// deterministically; a brand-new device key is generated for THIS device
// and self-authorized by a proof signed with the recovery-derived root
// key (the one path services/api/internal/identity's authorizesBinding
// accepts with "no further discretionary authority to reject it" — see
// sign.go). The identityRef itself is not recoverable from the phrase
// alone (it's a server-issued opaque ID, not derived data) — the charter's
// own single-guided-screen flow is for FIRST creation; a real "I lost
// everything" recovery UI must still ask the user for their identityRef
// (expected to have been written down or otherwise recorded alongside the
// phrase, matching the charter's plain-language warning about total,
// permanent loss if both are gone).
// ---------------------------------------------------------------------------
export async function restoreIdentityFlow(request: {
  recoveryPhrase: string;
  identityRef: string;
  deviceName: string;
}): Promise<OnboardingResult> {
  const restored = crypto.restoreFromRecoveryPhrase({ recoveryPhrase: request.recoveryPhrase });

  // epoch is only discoverable via a response payload (see
  // apps/mobile/src/capabilities/identity/index.ts's buildBindDeviceMessage
  // doc comment) — ResolveIdentity is the public, unauthenticated lookup
  // that gives us the CURRENT value to sign against, since this device has
  // no prior local record for this identity (that's the whole premise of
  // the recovery path).
  const resolved = await identity.resolveIdentity({ identityRef: request.identityRef });

  const deviceKeyPair = crypto.generateKeyPair({ purpose: DEVICE_KEY_PURPOSE });
  const message = identity.buildBindDeviceMessage(
    request.identityRef,
    deviceKeyPair.publicKey,
    request.deviceName,
    resolved.publicIdentity.epoch,
  );
  const { signature } = crypto.sign({ privateKeyHandle: restored.privateKeyHandle, message });

  const bound = await identity.bindDevice({
    identityRef: request.identityRef,
    devicePublicKey: deviceKeyPair.publicKey,
    deviceName: request.deviceName,
    authorizationProof: signature,
  });

  const localRecord: LocalIdentityRecord = {
    identityRef: request.identityRef,
    displayName: resolved.publicIdentity.displayName,
    deviceId: bound.device.deviceId,
    epoch: bound.epoch,
  };
  await saveLocalIdentity(localRecord);

  const session = await bootstrapSession(localRecord.identityRef, localRecord.deviceId, deviceKeyPair.privateKeyHandle);

  logAuditEvent("onboarding_identity_restored", {
    identityRef: localRecord.identityRef,
    deviceId: localRecord.deviceId,
  });

  return {
    identityRef: localRecord.identityRef,
    deviceId: localRecord.deviceId,
    epoch: localRecord.epoch,
    displayName: localRecord.displayName,
    sessionToken: session.sessionToken,
    expiresAtUnix: session.expiresAtUnix,
  };
}

// ---------------------------------------------------------------------------
// resumeSession — reuses a still-valid, previously-persisted session token
// on app relaunch, without requiring a fresh signature (see the KNOWN GAP
// note above: a fresh signature isn't possible after a process restart
// with the current crypto contract). Returns null if there's no local
// record, or the persisted token has already passed its expiresAtUnix
// (this module does not itself call ValidateSession — that's a real
// network round trip better left to whatever screen/query actually needs
// to confirm liveness, per this file's "no capability logic of its own"
// boundary).
// ---------------------------------------------------------------------------
export async function resumeSession(): Promise<{ identity: LocalIdentityRecord; session: LocalSessionRecord } | null> {
  const [localIdentity, localSessionRecord] = await Promise.all([loadLocalIdentity(), loadLocalSession()]);
  if (!localIdentity || !localSessionRecord) return null;
  if (localSessionRecord.expiresAtUnix * 1000 <= Date.now()) return null;

  setAuthToken(localSessionRecord.sessionToken);
  return { identity: localIdentity, session: localSessionRecord };
}

// ---------------------------------------------------------------------------
// removeDevice — Devices screen's default action. Composed per charter §5's
// ordering requirement (docs/DECISION_LOG.md, "Session/Request
// Authentication contract amendment: RevokeSessionsForDevice", and the
// charter's own §5 text): Identity's revokeDevice is called FIRST, so any
// new IssueSession attempt for this device is blocked (DeviceResolver,
// server-side) before sessionauth.revokeSessionsForDevice's revoke query
// runs — closing the composed action's own network-round-trip gap, per
// RevokeSessionsForDevice's atomicity requirement (charter §3) covering a
// session issued in that gap. The composed action is not complete until
// BOTH calls succeed — a revokeDevice success followed by a
// revokeSessionsForDevice failure is surfaced as a thrown error, not
// swallowed, so the caller (DevicesScreen) can tell the user the removal
// was only partially applied rather than reporting false success.
//
// Retry-recoverable (fixed 2026-08-18, Security Steward implementation-gate
// finding — see docs/DECISION_LOG.md): Identity.RevokeDevice is not
// idempotent (a second call for an already-revoked device returns 404
// ErrDeviceNotFound), so a naive retry after a first attempt's
// revokeSessionsForDevice call failed (device revoked, sessions not yet
// cleared) would fail immediately on the retry's revokeDevice call and
// never reach revokeSessionsForDevice again — leaving a bounded-but-real
// residual session window with no in-flow remedy. A 404 from revokeDevice
// is therefore treated as an already-satisfied precondition, not a
// failure: this call proceeds to revokeSessionsForDevice regardless,
// re-fetching the current epoch via the public resolveIdentity lookup
// (this device's removal already happened, we just don't have its return
// value from this call) so the response shape stays consistent.
// ---------------------------------------------------------------------------
export async function removeDevice(
  identityRef: string,
  deviceId: string,
  sessionToken: string,
): Promise<{ epoch: number; sessionsRevoked: number }> {
  let epoch: number;
  try {
    epoch = (await identity.revokeDevice({ identityRef, deviceId }, sessionToken)).epoch;
  } catch (err) {
    if (err instanceof ApiError && err.status === 404) {
      // Already revoked (e.g. a retry after a prior partial failure) —
      // satisfied precondition, not an error. Proceed to make sure this
      // device's sessions are actually cleared.
      epoch = (await identity.resolveIdentity({ identityRef })).publicIdentity.epoch;
    } else {
      throw err;
    }
  }
  const revokeSessionsResp = await sessionauth.revokeSessionsForDevice({
    callerSessionToken: sessionToken,
    deviceId,
  });
  logAuditEvent("onboarding_device_removed", {
    identityRef,
    deviceId,
    epochAfter: String(epoch),
    sessionsRevoked: String(revokeSessionsResp.sessionsRevoked),
  });
  return { epoch, sessionsRevoked: revokeSessionsResp.sessionsRevoked };
}

// ---------------------------------------------------------------------------
// signOutEverywhere — fully implementable, no gap (see charter §3: scoped
// to the caller's OWN resolved identity via callerSessionToken, unlike
// device-scoped revocation).
// ---------------------------------------------------------------------------
export async function signOutEverywhere(sessionToken: string): Promise<{ sessionsRevoked: number }> {
  const resp = await sessionauth.revokeAllSessions({ callerSessionToken: sessionToken });
  clearScheduledRenewal();
  activeDeviceKeyHandle = null;
  setAuthToken(null);
  // Minor known limitation, not worked around: Cryptography & Keys'
  // SecureLocalStore/Retrieve contract exposes no delete/remove
  // operation, so the now-revoked token persisted by bootstrapSession
  // above cannot be scrubbed from local storage here. This is safe (the
  // token is genuinely revoked server-side the instant this call
  // succeeds — Art. 7, real revocation not eventual expiry — so a stale
  // copy sitting in SecureLocalStore is inert, not a live credential) but
  // means resumeSession() on next launch will optimistically set a dead
  // token as the current bearer token until the first gated call 401s.
  logAuditEvent("onboarding_sign_out_everywhere", { sessionsRevoked: String(resp.sessionsRevoked) });
  return resp;
}
