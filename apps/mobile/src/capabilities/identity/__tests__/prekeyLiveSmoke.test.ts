// TEMPORARY, live-server-dependent smoke test — NOT part of the permanent
// suite, same precedent as
// apps/mobile/src/features/vault/__tests__/liveSmoke.test.ts and
// apps/mobile/src/features/onboarding/__tests__/liveSmoke.test.ts.
// Exercises the REAL identity capability client module's
// publishPrekeyBundle/fetchPrekeyBundle (not a hand-rolled protocol
// replica), and the REAL crypto capability client's generatePrekeyBundle,
// together against the real running `services/api` server at
// http://localhost:8080 — proving the actual wire encode/decode this pass
// added (base64 []byte fields, the PrekeyBundleStatus string enum, the
// device-binding-gated publish route, the open fetch route) round-trips
// correctly against real JSON the Go server produces, not just against
// this module's own TypeScript types.
import { createIdentityFlow } from "../../../features/onboarding/onboarding";
import * as identity from "../index";
import * as crypto from "../../crypto";
import { ApiError } from "../../../api/httpClient";

const RUN_LIVE = process.env.ASCEND_LIVE_SMOKE === "1";
const maybeDescribe = RUN_LIVE ? describe : describe.skip;

maybeDescribe("identity prekey bundle publish/fetch live smoke (real server)", () => {
  jest.setTimeout(30_000);

  it("publish (own device) -> fetch (different identity, consumes one-time prekey) -> exhaustion fallback -> unconsumedOneTimePrekeyCount", async () => {
    const alice = await createIdentityFlow({
      displayName: `Prekey Alice ${Date.now()}`,
      firstDeviceName: "Alice Device",
    });
    const bob = await createIdentityFlow({
      displayName: `Prekey Bob ${Date.now()}`,
      firstDeviceName: "Bob Device",
    });

    // Alice generates a real, signed bundle (Cryptography & Keys' own
    // client, not fabricated bytes) and publishes it for her own device.
    const bundle = await crypto.generatePrekeyBundle({ oneTimePrekeyCount: 1 });
    const publishResp = await identity.publishPrekeyBundle(
      {
        identityRef: alice.identityRef,
        deviceId: alice.deviceId,
        signedPrekey: bundle.signedPrekey,
        oneTimePrekeys: bundle.oneTimePrekeys,
        identityDhPublicKey: bundle.identityDhPublicKey,
        identityDhPublicKeySignature: bundle.identityDhPublicKeySignature,
      },
      alice.sessionToken,
    );
    expect(publishResp.publishedCount).toBe(1);

    // Bob — a completely different identity — fetches Alice's bundle using
    // HIS OWN session token (the deliberate openness, charter §3/§6).
    const fetchResp = await identity.fetchPrekeyBundle(
      { identityRef: alice.identityRef, deviceId: alice.deviceId },
      bob.sessionToken,
    );
    expect(fetchResp.status).toBe("PREKEY_BUNDLE_STATUS_AVAILABLE");
    expect(fetchResp.signedPrekey.prekeyId).toBe(bundle.signedPrekey.prekeyId);
    expect(fetchResp.oneTimePrekey?.prekeyId).toBe(bundle.oneTimePrekeys[0].prekeyId);
    // key-separation fix: identityDhPublicKey is Alice's DEVICE's stored
    // DH key (matches what she published), NEVER her identity's Ed25519
    // signing key — identitySigningPublicKey is that, and the two must
    // never be the same bytes.
    expect(fetchResp.identityDhPublicKey).toEqual(bundle.identityDhPublicKey);
    expect(fetchResp.identityDhPublicKeySignature).toEqual(bundle.identityDhPublicKeySignature);
    expect(fetchResp.identitySigningPublicKey.length).toBeGreaterThan(0);
    expect(fetchResp.identitySigningPublicKey).not.toEqual(fetchResp.identityDhPublicKey);

    // The pool is now empty — a second fetch hits the exhaustion-fallback
    // case: still AVAILABLE (a signed prekey exists), but no
    // oneTimePrekey.
    const secondFetch = await identity.fetchPrekeyBundle(
      { identityRef: alice.identityRef, deviceId: alice.deviceId },
      bob.sessionToken,
    );
    expect(secondFetch.status).toBe("PREKEY_BUNDLE_STATUS_AVAILABLE");
    expect(secondFetch.oneTimePrekey).toBeUndefined();

    // Alice's own ListDevices now shows 0 unconsumed one-time prekeys for
    // her device (the derived, self-only passive signal, charter §4/§6).
    const devices = await identity.listDevices({ identityRef: alice.identityRef }, alice.sessionToken);
    const aliceDevice = devices.devices.find((d) => d.deviceId === alice.deviceId);
    expect(aliceDevice?.unconsumedOneTimePrekeyCount).toBe(0);
  });

  it("a device that never published returns NOT_PUBLISHED, and Bob cannot publish for Alice's device", async () => {
    const alice = await createIdentityFlow({
      displayName: `Prekey Alice2 ${Date.now()}`,
      firstDeviceName: "Alice Device",
    });
    const bob = await createIdentityFlow({
      displayName: `Prekey Bob2 ${Date.now()}`,
      firstDeviceName: "Bob Device",
    });

    const neverPublished = await identity.fetchPrekeyBundle(
      { identityRef: alice.identityRef, deviceId: alice.deviceId },
      bob.sessionToken,
    );
    expect(neverPublished.status).toBe("PREKEY_BUNDLE_STATUS_NOT_PUBLISHED");
    expect(neverPublished.oneTimePrekey).toBeUndefined();

    const bundle = await crypto.generatePrekeyBundle({ oneTimePrekeyCount: 0 });
    await expect(
      identity.publishPrekeyBundle(
        {
          identityRef: alice.identityRef,
          deviceId: alice.deviceId,
          signedPrekey: bundle.signedPrekey,
          oneTimePrekeys: [],
          identityDhPublicKey: bundle.identityDhPublicKey,
          identityDhPublicKeySignature: bundle.identityDhPublicKeySignature,
        },
        bob.sessionToken, // Bob's own valid session, used against Alice's identity/device
      ),
    ).rejects.toMatchObject({ status: 403 } satisfies Partial<ApiError>);
  });
});
