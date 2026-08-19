// Vault — feature composition layer over the File Objects capability
// client (apps/mobile/src/capabilities/fileobjects/). Per
// apps/mobile/README.md's capability boundary and CLAUDE.md's
// "Capabilities vs. features" section, this file holds no capability logic
// of its own — every actual decision (is this read allowed, does this
// version exist, was this grant applied) is made by the real backend. This
// module only composes already-real RPC results into the shapes the
// screens need, mirroring apps/mobile/src/features/onboarding/onboarding.ts's
// own "composition, not a capability" precedent (not under
// apps/mobile/src/capabilities/, not subject to
// scripts/constitution/check-audit-events-ts.sh).
//
// buildTimeline is the one non-trivial piece of composition this feature
// needs: docs/capabilities/file-objects.charter.md §5 requires
// GetFileHistory and ListVersions to present as ONE merged surface, not two
// separate screens/tabs a user has to learn are different — "a single
// history/timeline view... with version-creation events shown inline among
// the other lifecycle events... each version-creation entry links directly
// to that version's content." File Objects' own charter (§6 point 8a)
// deliberately keeps GetFileHistory scoped to File Objects' own emitted
// events only — this module never reaches into Permissions'/Storage's own
// audit trails to build this timeline, only the two RPCs the charter names.
import type { FileEvent, FileObjectsPermissionAction, VersionSummary } from "../../capabilities/fileobjects";

export interface TimelineEntry {
  eventId: string;
  action: string;
  actor: string;
  occurredAtUnix: number;
  metadata: Record<string, string>;
  /**
   * Present for "fileobjects.create_file_object"/"fileobjects.create_version"
   * events whose metadata.version_ref (set server-side, see
   * services/api/internal/fileobjects/service.go's CreateFileObject/
   * CreateVersion) resolves to a version still present in the ListVersions
   * result. Screens use this to render a "view this version" link that
   * calls GetFileContent(versionRef=...) — charter §5's explicit
   * requirement. Absent for every other event type (permission changes,
   * metadata edits, deletion), which have no associated version.
   */
  linkedVersion?: VersionSummary;
}

/**
 * Merges GetFileHistory's events and ListVersions' summaries into one
 * timeline, newest first — the single surface charter §5 requires. Never
 * drops an event for lack of a resolvable version (a version could in
 * principle no longer be independently listed while its creation event
 * remains in history — defensive, not expected under the current server
 * implementation, which never removes a version once created).
 */
export function buildTimeline(events: FileEvent[], versions: VersionSummary[]): TimelineEntry[] {
  const versionsByRef = new Map(versions.map((v) => [v.versionRef, v]));

  const entries: TimelineEntry[] = events.map((event) => {
    const versionRef = event.metadata.version_ref;
    const linkedVersion = versionRef ? versionsByRef.get(versionRef) : undefined;
    return {
      eventId: event.eventId,
      action: event.action,
      actor: event.actor,
      occurredAtUnix: event.occurredAtUnix,
      metadata: event.metadata,
      linkedVersion,
    };
  });

  return entries.sort((a, b) => b.occurredAtUnix - a.occurredAtUnix);
}

/** Human-readable label for a FileEvent/TimelineEntry's `action` — every value service.go actually emits, plus a safe fallback for forward-compatibility (see fileobjects/types.ts's FileEvent doc comment on why `action` is not a closed TS union). */
export function describeAction(action: string): string {
  switch (action) {
    case "fileobjects.create_file_object":
      return "File created";
    case "fileobjects.create_version":
      return "New version";
    case "fileobjects.permission_granted":
      return "Access granted";
    case "fileobjects.permission_revoked":
      return "Access revoked";
    case "fileobjects.set_file_metadata":
      return "Details updated";
    case "fileobjects.delete_file_object":
      return "File deleted";
    default:
      return action;
  }
}

/**
 * Human-readable label for one AccessGrant's `action` (charter §3's
 * ListFileAccess) — the closed, two-value FileObjectsPermissionAction union
 * (charter §6 point 1), unlike describeAction's open-ended FileEvent.action
 * above. The `default` case is unreachable given the closed union type; it
 * exists only so TypeScript's control-flow analysis can see every path
 * returns a value.
 */
export function describePermissionAction(action: FileObjectsPermissionAction): string {
  switch (action) {
    case "fileobjects.read":
      return "Can view";
    case "fileobjects.write":
      return "Can edit";
    default:
      return action;
  }
}
