// TEMPORARY, live-server-dependent smoke test — NOT part of the permanent
// suite (see apps/mobile/src/features/onboarding/__tests__/liveSmoke.test.ts
// for the established precedent this mirrors). Exercises the REAL
// permissions capability client module (not a hand-rolled protocol
// replica) against the real running `services/api` server at
// http://localhost:8080, wired through onboarding.ts's real
// createIdentityFlow for two distinct identities (owner + recipient) and
// File Objects' real setFilePermissions (the only grant path mobile
// exposes — see capabilities/permissions/index.ts's header for why
// checkPermission/grantPermission/revokePermission aren't wrapped
// directly). This is the "PascalCase wrapper / snake_case Grant" mixed
// wire shape this pass's client module was built against, verified here
// byte-for-byte against the real server rather than trusted from reading
// Go source alone.
import { createIdentityFlow } from "../../onboarding/onboarding";
import * as fileobjects from "../../../capabilities/fileobjects";
import * as permissions from "../../../capabilities/permissions";

const RUN_LIVE = process.env.ASCEND_LIVE_SMOKE === "1";
const maybeDescribe = RUN_LIVE ? describe : describe.skip;

maybeDescribe("permissions live smoke (real server)", () => {
  jest.setTimeout(30_000);

  it("ListGrantsForSubject reflects a real share, and ExportPermissions returns a well-formed document for both parties", async () => {
    const owner = await createIdentityFlow({
      displayName: `Permissions Owner ${Date.now()}`,
      firstDeviceName: "Owner Device",
    });
    const recipient = await createIdentityFlow({
      displayName: `Permissions Recipient ${Date.now()}`,
      firstDeviceName: "Recipient Device",
    });

    // --- Create a file as owner, so owner already holds bootstrap grants
    // (fileobjects.read/write on this file_object) before any sharing
    // happens — these are what the owner's own ListGrantsForSubject
    // should already show, with no explicit share step required. ---
    const created = await fileobjects.createFileObject(
      {
        owner: owner.identityRef,
        requestingSubject: owner.identityRef,
        initialContent: new TextEncoder().encode("permissions smoke test content"),
        name: "permissions-smoke.txt",
        mimeType: "text/plain",
      },
      owner.sessionToken,
    );
    const fileObjectId = created.fileObject.fileObjectId;

    // --- Owner's own ListGrantsForSubject already shows the bootstrap
    // owner grant on this file_object, before any share. ---
    const ownerGrantsBefore = await permissions.listGrantsForSubject(
      { subject: owner.identityRef },
      owner.sessionToken,
    );
    const ownerFileGrant = ownerGrantsBefore.grants.find(
      (g) => g.resource.resourceType === "file_object" && g.resource.resourceId === fileObjectId && g.action === "fileobjects.read",
    );
    expect(ownerFileGrant).toBeDefined();
    expect(ownerFileGrant?.scope).toBe("full");
    expect(ownerFileGrant?.grantor).toBe(owner.identityRef);
    expect(ownerFileGrant?.subject).toBe(owner.identityRef);
    expect(ownerFileGrant?.grantedAtUnix).toBeGreaterThan(0);

    // --- Recipient holds nothing on this resource yet. ---
    const recipientGrantsBefore = await permissions.listGrantsForSubject(
      { subject: recipient.identityRef },
      recipient.sessionToken,
    );
    expect(
      recipientGrantsBefore.grants.some(
        (g) => g.resource.resourceType === "file_object" && g.resource.resourceId === fileObjectId,
      ),
    ).toBe(false);

    // --- A caller may only list their own grants (server-side
    // enforcement, this module never attempts to work around it). ---
    await expect(permissions.listGrantsForSubject({ subject: owner.identityRef }, recipient.sessionToken)).rejects.toThrow();

    // --- Share via File Objects' own SetFilePermissions — the only grant
    // path mobile exposes. ---
    await fileobjects.setFilePermissions(
      {
        fileObjectId,
        requestingSubject: owner.identityRef,
        grant: true,
        subject: recipient.identityRef,
        action: "fileobjects.read",
        scope: "full",
      },
      owner.sessionToken,
    );

    // --- Recipient's own "what can I access" view now shows it. ---
    const recipientGrantsAfter = await permissions.listGrantsForSubject(
      { subject: recipient.identityRef },
      recipient.sessionToken,
    );
    const recipientFileGrant = recipientGrantsAfter.grants.find(
      (g) => g.resource.resourceType === "file_object" && g.resource.resourceId === fileObjectId,
    );
    expect(recipientFileGrant).toEqual(
      expect.objectContaining({
        grantor: owner.identityRef,
        subject: recipient.identityRef,
        action: "fileobjects.read",
        scope: "full",
      }),
    );

    // --- ExportPermissions (Art. 9) — both parties get a well-formed,
    // versioned document reflecting reality. ---
    const ownerExport = await permissions.exportPermissions({ identityRef: owner.identityRef }, owner.sessionToken);
    expect(ownerExport.formatVersion).toBe("ascend-permissions-export-v1");
    const ownerDoc = JSON.parse(new TextDecoder().decode(ownerExport.exportBlob));
    expect(ownerDoc.identity_ref).toBe(owner.identityRef);
    expect(
      ownerDoc.active_grants.some(
        (g: { resource: { resource_id: string } }) => g.resource.resource_id === fileObjectId,
      ),
    ).toBe(true);
    expect(ownerDoc.history.length).toBeGreaterThan(0);

    const recipientExport = await permissions.exportPermissions(
      { identityRef: recipient.identityRef },
      recipient.sessionToken,
    );
    const recipientDoc = JSON.parse(new TextDecoder().decode(recipientExport.exportBlob));
    expect(recipientDoc.identity_ref).toBe(recipient.identityRef);
    expect(
      recipientDoc.active_grants.some(
        (g: { resource: { resource_id: string } }) => g.resource.resource_id === fileObjectId,
      ),
    ).toBe(true);

    // --- A caller may only export their own permissions. ---
    await expect(
      permissions.exportPermissions({ identityRef: owner.identityRef }, recipient.sessionToken),
    ).rejects.toThrow();
  });
});
