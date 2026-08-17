// TEMPORARY, live-server-dependent smoke test — NOT part of the permanent
// suite (deleted after this pass's manual verification run; see
// docs/DECISION_LOG.md, 2026-08-17, this pass's entry, "Live verification"
// section). Exercises the REAL onboarding.ts/identity/sessionauth module
// code (not a hand-rolled protocol replica) against the real running
// `services/api` server at http://localhost:8080.
import { createIdentityFlow, restoreIdentityFlow, removeDevice, signOutEverywhere } from "../onboarding";
import * as identity from "../../../capabilities/identity";
import * as sessionauth from "../../../capabilities/sessionauth";

const RUN_LIVE = process.env.ASCEND_LIVE_SMOKE === "1";
const maybeDescribe = RUN_LIVE ? describe : describe.skip;

maybeDescribe("onboarding live smoke (real server)", () => {
  jest.setTimeout(30_000);

  it("createIdentityFlow -> Devices/Sessions listing -> bindDevice(second device) -> removeDevice -> signOutEverywhere", async () => {
    const displayName = `Live Smoke ${Date.now()}`;
    const created = await createIdentityFlow({ displayName, firstDeviceName: "Device One" });

    expect(created.identityRef).toBeTruthy();
    expect(created.deviceId).toBeTruthy();
    expect(created.sessionToken).toBeTruthy();
    expect(created.recoveryPhrase.split(" ")).toHaveLength(24);
    expect(created.epoch).toBe(0);

    // ListDevices (gated, real bearer token) sees exactly the first device.
    const devicesResp = await identity.listDevices({ identityRef: created.identityRef }, created.sessionToken);
    expect(devicesResp.devices).toHaveLength(1);
    expect(devicesResp.devices[0].deviceId).toBe(created.deviceId);

    // ListActiveSessions sees exactly this session, with no sessionToken field.
    const sessionsResp = await sessionauth.listActiveSessions(created.sessionToken);
    expect(sessionsResp.sessions).toHaveLength(1);
    expect(sessionsResp.sessions[0].deviceId).toBe(created.deviceId);
    expect("sessionToken" in sessionsResp.sessions[0]).toBe(false);

    // ExportIdentity / ExportSessions both succeed and contain no live token.
    const exportedIdentity = await identity.exportIdentity({ identityRef: created.identityRef }, created.sessionToken);
    expect(exportedIdentity.formatVersion).toBe("ascend-identity-export-v1");
    const exportedSessions = await sessionauth.exportSessions(created.sessionToken);
    expect(exportedSessions.formatVersion).toBe("ascend-sessionauth-export-v1");
    expect(new TextDecoder().decode(exportedSessions.exportBlob)).not.toContain(created.sessionToken);

    // restoreIdentityFlow: recovery-phrase path binds a genuinely new
    // device using the recovery-derived root key, then bootstraps its own
    // independent session.
    const restored = await restoreIdentityFlow({
      recoveryPhrase: created.recoveryPhrase,
      identityRef: created.identityRef,
      deviceName: "Recovered Device",
    });
    expect(restored.deviceId).not.toBe(created.deviceId);
    expect(restored.epoch).toBe(1);
    expect(restored.sessionToken).not.toBe(created.sessionToken);

    // removeDevice (identity.charter.md's RevokeDevice, via onboarding's
    // documented-gap wrapper): removes the recovered device's binding.
    const removed = await removeDevice(created.identityRef, restored.deviceId, created.sessionToken);
    expect(removed.epoch).toBe(2);

    const devicesAfterRemoval = await identity.listDevices({ identityRef: created.identityRef }, created.sessionToken);
    expect(devicesAfterRemoval.devices.map((d) => d.deviceId)).not.toContain(restored.deviceId);

    // signOutEverywhere: fully implementable, no gap — revokes ALL of this
    // identity's sessions, including the one used to authorize it.
    const revokedAll = await signOutEverywhere(created.sessionToken);
    expect(revokedAll.sessionsRevoked).toBeGreaterThanOrEqual(1);

    await expect(sessionauth.listActiveSessions(created.sessionToken)).rejects.toThrow();
  });
});
