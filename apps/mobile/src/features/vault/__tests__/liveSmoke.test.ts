// TEMPORARY, live-server-dependent smoke test — NOT part of the permanent
// suite (see apps/mobile/src/features/onboarding/__tests__/liveSmoke.test.ts
// for the established precedent this mirrors). Exercises the REAL
// fileobjects capability client module (not a hand-rolled protocol
// replica) against the real running `services/api` server at
// http://localhost:8080, wired through onboarding.ts's real
// createIdentityFlow for two distinct identities (sharer + recipient) —
// this is exactly the "no /v1 prefix, PascalCase wire body, bearer session
// token" surface this pass's client module was built against, verified
// here byte-for-byte against the real server rather than trusted from
// reading Go source alone.
import { createIdentityFlow } from "../../onboarding/onboarding";
import * as fileobjects from "../../../capabilities/fileobjects";
import { ApiError } from "../../../api/httpClient";

const RUN_LIVE = process.env.ASCEND_LIVE_SMOKE === "1";
const maybeDescribe = RUN_LIVE ? describe : describe.skip;

maybeDescribe("vault (File Objects) live smoke (real server)", () => {
  jest.setTimeout(30_000);

  it("create -> list -> share -> open-by-id (recipient) -> deny write (recipient) -> export -> delete -> history survives", async () => {
    const owner = await createIdentityFlow({
      displayName: `Vault Owner ${Date.now()}`,
      firstDeviceName: "Owner Device",
    });
    const recipient = await createIdentityFlow({
      displayName: `Vault Recipient ${Date.now()}`,
      firstDeviceName: "Recipient Device",
    });

    const originalContent = new TextEncoder().encode("hello from the live smoke test");

    // --- CreateFileObject ---
    const created = await fileobjects.createFileObject(
      {
        owner: owner.identityRef,
        requestingSubject: owner.identityRef,
        initialContent: originalContent,
        name: "smoke-test.txt",
        mimeType: "text/plain",
      },
      owner.sessionToken,
    );
    expect(created.fileObject.fileObjectId).toBeTruthy();
    expect(created.fileObject.owner).toBe(owner.identityRef);
    expect(created.fileObject.sizeBytes).toBe(originalContent.byteLength);
    // blob_ref must never appear anywhere on this response (charter §6 point 8).
    expect(JSON.stringify(created.fileObject)).not.toMatch(/blob/i);
    const fileObjectId = created.fileObject.fileObjectId;

    // --- ListFileObjects (self-only) sees exactly this file ---
    const ownerList = await fileobjects.listFileObjects(
      { owner: owner.identityRef, requestingSubject: owner.identityRef },
      owner.sessionToken,
    );
    expect(ownerList.fileObjects.map((f) => f.fileObjectId)).toContain(fileObjectId);

    // --- GetFileContent (owner) round-trips exactly ---
    const ownerContent = await fileobjects.getFileContent(
      { fileObjectId, requestingSubject: owner.identityRef },
      owner.sessionToken,
    );
    expect(new TextDecoder().decode(ownerContent.content)).toBe("hello from the live smoke test");

    // --- Recipient cannot see it via their own ListFileObjects (not shared yet, and never would appear there anyway — it's not theirs) ---
    const recipientListBefore = await fileobjects.listFileObjects(
      { owner: recipient.identityRef, requestingSubject: recipient.identityRef },
      recipient.sessionToken,
    );
    expect(recipientListBefore.fileObjects.map((f) => f.fileObjectId)).not.toContain(fileObjectId);

    // --- Recipient cannot open it yet (no grant) ---
    await expect(
      fileobjects.getFileMetadata({ fileObjectId, requestingSubject: recipient.identityRef }, recipient.sessionToken),
    ).rejects.toThrow();

    // --- Share: grant recipient fileobjects.read ---
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

    // --- Recipient opens by ID (charter §7's documented interim flow) ---
    const recipientMeta = await fileobjects.getFileMetadata(
      { fileObjectId, requestingSubject: recipient.identityRef },
      recipient.sessionToken,
    );
    expect(recipientMeta.name).toBe("smoke-test.txt");

    const recipientContent = await fileobjects.getFileContent(
      { fileObjectId, requestingSubject: recipient.identityRef },
      recipient.sessionToken,
    );
    expect(new TextDecoder().decode(recipientContent.content)).toBe("hello from the live smoke test");

    // Recipient's own ListFileObjects still never surfaces an owned-by-someone-else file.
    const recipientListAfter = await fileobjects.listFileObjects(
      { owner: recipient.identityRef, requestingSubject: recipient.identityRef },
      recipient.sessionToken,
    );
    expect(recipientListAfter.fileObjects.map((f) => f.fileObjectId)).not.toContain(fileObjectId);

    // --- Recipient holds read only — a write attempt is denied ---
    let writeDenied = false;
    try {
      await fileobjects.setFileMetadata(
        { fileObjectId, requestingSubject: recipient.identityRef, name: "hijacked.txt" },
        recipient.sessionToken,
      );
    } catch (err) {
      writeDenied = err instanceof ApiError && err.status === 403;
    }
    expect(writeDenied).toBe(true);

    // --- Merged history/version timeline data is real: GetFileHistory + ListVersions ---
    const history = await fileobjects.getFileHistory(
      { fileObjectId, requestingSubject: owner.identityRef },
      owner.sessionToken,
    );
    expect(history.events.map((e) => e.action)).toEqual(
      expect.arrayContaining(["fileobjects.create_file_object", "fileobjects.permission_granted"]),
    );
    expect(JSON.stringify(history.events)).not.toMatch(/blob/i);

    const versions = await fileobjects.listVersions(
      { fileObjectId, requestingSubject: owner.identityRef },
      owner.sessionToken,
    );
    expect(versions.versions).toHaveLength(1);

    // --- Owner renames/retags (SetFileMetadata) ---
    await fileobjects.setFileMetadata(
      { fileObjectId, requestingSubject: owner.identityRef, name: "renamed.txt", tags: ["smoke", "live"] },
      owner.sessionToken,
    );
    const renamedMeta = await fileobjects.getFileMetadata(
      { fileObjectId, requestingSubject: owner.identityRef },
      owner.sessionToken,
    );
    expect(renamedMeta.name).toBe("renamed.txt");
    expect(renamedMeta.tags).toEqual(["smoke", "live"]);

    // --- Export (Art. 9) ---
    const exported = await fileobjects.exportFile(
      { fileObjectId, requestingSubject: owner.identityRef },
      owner.sessionToken,
    );
    expect(exported.formatVersion).toBe("ascend-fileobjects-export-v1");
    const exportedDoc = JSON.parse(new TextDecoder().decode(exported.exportBlob));
    expect(exportedDoc.fileObjectId).toBe(fileObjectId);
    expect(exportedDoc.versions).toHaveLength(1);
    expect(exportedDoc.versions[0].blobRef).toBeUndefined();

    // --- Delete ---
    await fileobjects.deleteFileObject({ fileObjectId, requestingSubject: owner.identityRef }, owner.sessionToken);

    // Content becomes unreachable...
    await expect(
      fileobjects.getFileContent({ fileObjectId, requestingSubject: owner.identityRef }, owner.sessionToken),
    ).rejects.toThrow();

    // ...but identity/history remain resolvable (charter §3).
    const historyAfterDelete = await fileobjects.getFileHistory(
      { fileObjectId, requestingSubject: owner.identityRef },
      owner.sessionToken,
    );
    expect(historyAfterDelete.events.map((e) => e.action)).toContain("fileobjects.delete_file_object");

    // Deleted file no longer appears in the owner's own inventory listing.
    const ownerListAfterDelete = await fileobjects.listFileObjects(
      { owner: owner.identityRef, requestingSubject: owner.identityRef },
      owner.sessionToken,
    );
    expect(ownerListAfterDelete.fileObjects.map((f) => f.fileObjectId)).not.toContain(fileObjectId);
  });
});
