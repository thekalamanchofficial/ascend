// TEMPORARY, live-server-dependent smoke test — NOT part of the permanent
// suite (see apps/mobile/src/features/onboarding/__tests__/liveSmoke.test.ts
// for the established precedent this mirrors, and
// apps/mobile/src/features/permissions/__tests__/liveSmoke.test.ts for the
// most recent sibling pass this one follows exactly). Exercises the REAL
// audit capability client module (not a hand-rolled protocol replica)
// against the real running `services/api` server at http://localhost:8080,
// wired through onboarding.ts's real createIdentityFlow (which itself
// triggers a real, server-emitted "identity.created" audit event — see
// services/api/internal/identity/service.go — so there is always at least
// one real event to query/explain/export without this test needing to call
// Emit directly, which this capability's mobile client deliberately does
// not wrap) and File Objects' real createFileObject (a second, distinct
// action/resource for filter coverage).
import { createIdentityFlow } from "../../onboarding/onboarding";
import * as fileobjects from "../../../capabilities/fileobjects";
import * as audit from "../../../capabilities/audit";

const RUN_LIVE = process.env.ASCEND_LIVE_SMOKE === "1";
const maybeDescribe = RUN_LIVE ? describe : describe.skip;

maybeDescribe("audit live smoke (real server)", () => {
  jest.setTimeout(30_000);

  it("Query reflects real events, Explain returns a rationale, ExportAuditTrail returns a well-formed hash-chained document, all self-only", async () => {
    const owner = await createIdentityFlow({
      displayName: `Audit Owner ${Date.now()}`,
      firstDeviceName: "Owner Device",
    });
    const other = await createIdentityFlow({
      displayName: `Audit Other ${Date.now()}`,
      firstDeviceName: "Other Device",
    });

    // --- Owner's own trail already shows the real, server-emitted
    // "identity.created" event from createIdentityFlow above, with no
    // explicit Emit call from this test (this module deliberately doesn't
    // wrap Emit — see capabilities/audit/index.ts's header). ---
    const ownerTrailBefore = await audit.query({ subject: owner.identityRef }, owner.sessionToken);
    const identityCreatedEvent = ownerTrailBefore.events.find(
      (e) => e.action === "identity.created" && e.resource.resourceType === "identity" && e.resource.resourceId === owner.identityRef,
    );
    expect(identityCreatedEvent).toBeDefined();
    expect(identityCreatedEvent?.actor).toBe(owner.identityRef);
    expect(identityCreatedEvent?.occurredAtUnix).toBeGreaterThan(0);
    expect(identityCreatedEvent?.eventId).toBeTruthy();

    // --- A caller may only query their own trail (fail-closed
    // PermissionChecker — services/api/internal/audit/service.go's
    // denyAllChecker default). ---
    await expect(audit.query({ subject: owner.identityRef }, other.sessionToken)).rejects.toThrow();

    // --- Create a file as owner, so a second, distinct action/resource
    // exists on the owner's trail for filter coverage. ---
    const created = await fileobjects.createFileObject(
      {
        owner: owner.identityRef,
        requestingSubject: owner.identityRef,
        initialContent: new TextEncoder().encode("audit smoke test content"),
        name: "audit-smoke.txt",
        mimeType: "text/plain",
      },
      owner.sessionToken,
    );
    const fileObjectId = created.fileObject.fileObjectId;

    // --- resourceTypeFilter/actionFilter narrow the trail to just the new
    // event (charter §3's QueryRequest fields). ---
    const filtered = await audit.query(
      { subject: owner.identityRef, resourceTypeFilter: "file_object", actionFilter: "fileobjects.create_file_object" },
      owner.sessionToken,
    );
    const createFileEvent = filtered.events.find((e) => e.resource.resourceId === fileObjectId);
    expect(createFileEvent).toBeDefined();
    expect(createFileEvent?.action).toBe("fileobjects.create_file_object");
    expect(createFileEvent?.actor).toBe(owner.identityRef);
    // The identity.created event must NOT show up under this narrower filter.
    expect(filtered.events.some((e) => e.action === "identity.created")).toBe(false);

    // --- A future-only time window returns nothing (sinceUnix filter is
    // real, not ignored). ---
    const futureOnly = await audit.query(
      { subject: owner.identityRef, sinceUnix: Math.floor(Date.now() / 1000) + 3600 },
      owner.sessionToken,
    );
    expect(futureOnly.events.length).toBe(0);

    // --- Explain turns the identity.created event into a plain-language
    // rationale (charter §3), for the owner. ---
    const explained = await audit.explain({ eventId: identityCreatedEvent!.eventId }, owner.sessionToken);
    expect(explained.humanReadableRationale.length).toBeGreaterThan(0);
    expect(explained.humanReadableRationale).toEqual(expect.any(String));

    // --- Explain is likewise self-or-permitted only — a non-actor,
    // non-permitted caller is denied. ---
    await expect(audit.explain({ eventId: identityCreatedEvent!.eventId }, other.sessionToken)).rejects.toThrow();

    // --- ExportAuditTrail (Art. 9) — a well-formed, versioned,
    // independently-verifiable document reflecting reality. Unlike
    // Identity's/Permissions' export RPCs, this is NOT a JSON envelope
    // around a base64 exportBlob — exportBlob IS the raw export bundle
    // bytes (see capabilities/audit/types.ts's header). ---
    const ownerExport = await audit.exportAuditTrail({ identityRef: owner.identityRef }, owner.sessionToken);
    expect(ownerExport.formatVersion).toBe("ascend-audit-export-v1");
    const ownerDoc = JSON.parse(new TextDecoder().decode(ownerExport.exportBlob));
    expect(ownerDoc.format_version).toBe("ascend-audit-export-v1");
    expect(ownerDoc.identity_ref).toBe(owner.identityRef);
    expect(typeof ownerDoc.verification_note).toBe("string");
    expect(ownerDoc.verification_note.length).toBeGreaterThan(0);
    expect(Array.isArray(ownerDoc.events)).toBe(true);
    expect(ownerDoc.events.length).toBeGreaterThanOrEqual(2); // identity.created + fileobjects.create_file_object
    expect(
      ownerDoc.events.some((e: { action: string; event_id: string }) => e.action === "identity.created" && e.event_id),
    ).toBe(true);
    expect(
      ownerDoc.events.some(
        (e: { action: string; resource: { resource_id: string } }) =>
          e.action === "fileobjects.create_file_object" && e.resource.resource_id === fileObjectId,
      ),
    ).toBe(true);
    // Hash-chain linkage (charter §6 tamper-evidence): every exported
    // record carries a prev_hash field, and the events are in ascending
    // occurred_at_unix order (export.go's sortByOccurredAscending — "so a
    // reader/verifier can walk the hash chain forward exactly as it was
    // built"). This test deliberately does NOT assert that a later
    // event's prev_hash equals an earlier event's event_id WITHIN this
    // bundle: per types.go's own doc comment, prev_hash links to the
    // immediately preceding event in the GLOBAL, cross-subject append
    // chain, not a per-subject-filtered one — with a second identity
    // (`other`) also being created concurrently against a real shared
    // server in this same test (and possibly others running in
    // parallel), this identity's own two exported events are not
    // guaranteed to be back-to-back in that global chain. Full-chain
    // verification (recomputing every hash across every subject) is
    // exactly what the export bundle's own verification_note documents as
    // possible for someone with the full, unfiltered trail — out of scope
    // for what a self-scoped ExportAuditTrail caller can independently
    // confirm about their own filtered slice.
    expect(ownerDoc.events.every((e: { prev_hash: unknown }) => typeof e.prev_hash === "string")).toBe(true);
    const occurredTimestamps = ownerDoc.events.map((e: { occurred_at_unix: number }) => e.occurred_at_unix);
    const sorted = [...occurredTimestamps].sort((a, b) => a - b);
    expect(occurredTimestamps).toEqual(sorted);

    // --- A caller may only export their own trail. ---
    await expect(audit.exportAuditTrail({ identityRef: owner.identityRef }, other.sessionToken)).rejects.toThrow();
  });
});
