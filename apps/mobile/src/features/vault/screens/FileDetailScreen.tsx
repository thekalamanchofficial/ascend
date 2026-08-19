// File detail — metadata plus ONE merged history/version timeline (charter
// §5's explicit requirement: GetFileHistory and ListVersions composed into
// one surface, not two the user has to learn are different — no separate
// "Versions" tab/screen). "Powerful when needed": rename/retag, export,
// delete, and share are all available but not pre-expanded — each is a
// single tap/section away, matching the charter's "powerful when needed"
// budget.
//
// Works identically whether reached from FilesListScreen (an owned file)
// or OpenSharedFileScreen (a file shared to this identity by someone else,
// opened by file_object_id — charter §3/§7's documented interim flow,
// since no "shared with me" discovery composition exists yet). This screen
// never decides what a non-owner may do — every action below simply calls
// the real RPC and surfaces whatever the server allows/denies (a
// non-owner's write/share/delete attempt fails with a 403 ApiError, shown
// inline like any other error here).
import * as React from "react";
import { View, Text, TextInput, Pressable, ActivityIndicator, ScrollView, Alert } from "react-native";
import { useNavigation, useRoute } from "@react-navigation/native";
import type { RouteProp } from "@react-navigation/native";
import type { RootStackParamList, NativeStackNavigationProp } from "../../../navigation/types";
import { ApiError } from "../../../api/httpClient";
import * as fileobjects from "../../../capabilities/fileobjects";
import type { AccessGrant, FileObjectsPermissionAction, GetFileMetadataResponse } from "../../../capabilities/fileobjects";
import { buildTimeline, describeAction, describePermissionAction } from "../vault";
import type { TimelineEntry } from "../vault";

type FileDetailRouteProp = RouteProp<RootStackParamList, "FileDetail">;

function formatUnixSeconds(unixSeconds: number): string {
  if (!unixSeconds) return "—";
  return new Date(unixSeconds * 1000).toLocaleString();
}

export function FileDetailScreen() {
  const navigation = useNavigation<NativeStackNavigationProp>();
  const route = useRoute<FileDetailRouteProp>();
  const { identityRef, sessionToken, fileObjectId, knownOwner } = route.params;

  const [metadata, setMetadata] = React.useState<GetFileMetadataResponse | null>(null);
  const [timeline, setTimeline] = React.useState<TimelineEntry[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState<string | null>(null);
  const [busyAction, setBusyAction] = React.useState<string | null>(null);
  const [exportText, setExportText] = React.useState<{ title: string; text: string } | null>(null);
  const [content, setContent] = React.useState<{ title: string; text: string } | null>(null);

  const [editing, setEditing] = React.useState(false);
  const [nameDraft, setNameDraft] = React.useState("");
  const [tagsDraft, setTagsDraft] = React.useState("");

  // "Who has access" (charter §3's ListFileAccess, frozen 2026-08-18) —
  // owner-only server-side. `accessGrants === null` means either "not
  // fetched yet" or "the server denied it" — both render as "don't show
  // this affordance at all", never as an error, per this screen's own
  // established precedent of never gating a UI element on inferred
  // ownership (see this file's header comment) and per the task's explicit
  // instruction to hide-on-403 rather than surface a permission error for a
  // perfectly ordinary "you don't own this file" case.
  const [accessGrants, setAccessGrants] = React.useState<AccessGrant[] | null>(null);
  const [accessExpanded, setAccessExpanded] = React.useState(false);

  const loadAccessGrants = React.useCallback(async () => {
    // knownOwner is a display-only hint (see navigation/types.ts) carried
    // over from FilesListScreen's own ListFileObjects result — when it's
    // present and names someone else, we already know client-side this
    // call would be denied, so skip the round trip entirely. When it's
    // absent (a file reached via OpenSharedFileScreen's manual-ID entry,
    // where ownership is genuinely unknown until the server answers) we
    // still attempt it and hide gracefully on a 403.
    if (knownOwner !== undefined && knownOwner !== identityRef) {
      setAccessGrants(null);
      return;
    }
    try {
      const resp = await fileobjects.listFileAccess({ fileObjectId, requestingSubject: identityRef }, sessionToken);
      setAccessGrants(resp.grants);
    } catch (err) {
      if (err instanceof ApiError && err.status === 403) {
        setAccessGrants(null); // not the owner — hide the affordance, not an error
        return;
      }
      // An unexpected failure (network, 500, ...) — don't block the rest of
      // this screen from rendering over a "who has access" hiccup; simply
      // leave the affordance hidden. Metadata/history errors above already
      // have their own dedicated error surface.
      setAccessGrants(null);
    }
  }, [fileObjectId, identityRef, sessionToken, knownOwner]);

  const load = React.useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [metaResp, historyResp, versionsResp] = await Promise.all([
        fileobjects.getFileMetadata({ fileObjectId, requestingSubject: identityRef }, sessionToken),
        fileobjects.getFileHistory({ fileObjectId, requestingSubject: identityRef }, sessionToken),
        fileobjects.listVersions({ fileObjectId, requestingSubject: identityRef }, sessionToken),
      ]);
      setMetadata(metaResp);
      setNameDraft(metaResp.name);
      setTagsDraft(metaResp.tags.join(", "));
      setTimeline(buildTimeline(historyResp.events, versionsResp.versions));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
    // Deliberately not awaited into the same try/catch above — a denied
    // (or failed) access-list fetch must never block metadata/history from
    // rendering.
    void loadAccessGrants();
  }, [fileObjectId, identityRef, sessionToken, loadAccessGrants]);

  React.useEffect(() => {
    load();
  }, [load]);

  async function handleOpenVersion(versionRef?: string, label?: string) {
    setBusyAction(`open:${versionRef ?? "current"}`);
    setError(null);
    try {
      const resp = await fileobjects.getFileContent(
        { fileObjectId, requestingSubject: identityRef, versionRef },
        sessionToken,
      );
      setContent({
        title: label ?? "Current version",
        text: decodeForDisplay(resp.content, metadata?.mimeType),
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusyAction(null);
    }
  }

  async function handleSaveMetadata() {
    setBusyAction("saveMetadata");
    setError(null);
    try {
      await fileobjects.setFileMetadata(
        {
          fileObjectId,
          requestingSubject: identityRef,
          name: nameDraft,
          tags: tagsDraft
            .split(",")
            .map((t) => t.trim())
            .filter((t) => t.length > 0),
        },
        sessionToken,
      );
      setEditing(false);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusyAction(null);
    }
  }

  async function handleExport() {
    setBusyAction("export");
    setError(null);
    try {
      const resp = await fileobjects.exportFile({ fileObjectId, requestingSubject: identityRef }, sessionToken);
      setExportText({
        title: `Export (${resp.formatVersion})`,
        text: new TextDecoder().decode(resp.exportBlob),
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusyAction(null);
    }
  }

  // Revoking is exactly SetFilePermissions(grant=false, ...) — File
  // Objects' contract already exposes this; no new revoke RPC is invented
  // here (per the task's explicit instruction).
  async function handleRevokeAccess(subject: string, action: FileObjectsPermissionAction) {
    setBusyAction(`revokeAccess:${subject}:${action}`);
    setError(null);
    try {
      await fileobjects.setFilePermissions(
        { fileObjectId, requestingSubject: identityRef, grant: false, subject, action, scope: "" },
        sessionToken,
      );
      await loadAccessGrants();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusyAction(null);
    }
  }

  function confirmDelete() {
    Alert.alert(
      "Delete file",
      `Delete "${metadata?.name || "this file"}"? This permanently destroys its content — this cannot be undone.`,
      [
        { text: "Cancel", style: "cancel" },
        {
          text: "Delete",
          style: "destructive",
          onPress: async () => {
            setBusyAction("delete");
            setError(null);
            try {
              await fileobjects.deleteFileObject({ fileObjectId, requestingSubject: identityRef }, sessionToken);
              navigation.goBack();
            } catch (err) {
              setError(err instanceof Error ? err.message : String(err));
              setBusyAction(null);
            }
          },
        },
      ],
    );
  }

  if (loading) {
    return (
      <View style={{ flex: 1, alignItems: "center", justifyContent: "center" }}>
        <ActivityIndicator />
      </View>
    );
  }

  return (
    <ScrollView contentContainerStyle={{ padding: 24, gap: 16 }}>
      {error ? <Text style={{ color: "#b00020" }}>{error}</Text> : null}

      {editing ? (
        <View style={{ gap: 8 }}>
          <Text>Name</Text>
          <TextInput
            value={nameDraft}
            onChangeText={setNameDraft}
            style={{ borderWidth: 1, borderColor: "#999", borderRadius: 6, padding: 10 }}
          />
          <Text>Tags (comma-separated)</Text>
          <TextInput
            value={tagsDraft}
            onChangeText={setTagsDraft}
            style={{ borderWidth: 1, borderColor: "#999", borderRadius: 6, padding: 10 }}
          />
          <View style={{ flexDirection: "row", gap: 12 }}>
            <Pressable disabled={busyAction === "saveMetadata"} onPress={handleSaveMetadata}>
              <Text style={{ fontWeight: "600" }}>{busyAction === "saveMetadata" ? "Saving…" : "Save"}</Text>
            </Pressable>
            <Pressable onPress={() => setEditing(false)}>
              <Text>Cancel</Text>
            </Pressable>
          </View>
        </View>
      ) : (
        <View style={{ gap: 4 }}>
          <Text style={{ fontSize: 20, fontWeight: "600" }}>{metadata?.name || "(untitled)"}</Text>
          <Text style={{ color: "#666" }}>{metadata?.mimeType || "unknown type"}</Text>
          <Text style={{ color: "#666" }}>{metadata ? formatBytes(metadata.sizeBytes) : ""}</Text>
          {knownOwner ? <Text style={{ color: "#666" }}>Owner: {knownOwner}</Text> : null}
          {metadata && metadata.tags.length > 0 ? (
            <Text style={{ color: "#666" }}>Tags: {metadata.tags.join(", ")}</Text>
          ) : null}
          <Pressable onPress={() => setEditing(true)} style={{ marginTop: 4 }}>
            <Text style={{ textDecorationLine: "underline" }}>Rename / edit tags</Text>
          </Pressable>
        </View>
      )}

      <Pressable
        disabled={busyAction === "open:current"}
        onPress={() => handleOpenVersion(undefined, "Current version")}
        style={{ borderWidth: 1, borderColor: "#111", padding: 12, borderRadius: 8, alignItems: "center" }}
      >
        <Text>{busyAction === "open:current" ? "Opening…" : "Open current version"}</Text>
      </Pressable>

      <View style={{ flexDirection: "row", gap: 16 }}>
        <Pressable onPress={() => navigation.navigate("ShareFile", { identityRef, sessionToken, fileObjectId })}>
          <Text style={{ textDecorationLine: "underline" }}>Share</Text>
        </Pressable>
        <Pressable disabled={busyAction === "export"} onPress={handleExport}>
          <Text style={{ textDecorationLine: "underline" }}>{busyAction === "export" ? "Exporting…" : "Export"}</Text>
        </Pressable>
        <Pressable disabled={busyAction === "delete"} onPress={confirmDelete}>
          <Text style={{ color: "#b00020", textDecorationLine: "underline" }}>
            {busyAction === "delete" ? "Deleting…" : "Delete"}
          </Text>
        </Pressable>
      </View>

      {accessGrants !== null ? (
        <View style={{ gap: 8 }}>
          <Pressable onPress={() => setAccessExpanded((v) => !v)}>
            <Text style={{ fontSize: 16, fontWeight: "600", textDecorationLine: "underline" }}>
              Who has access ({accessGrants.length}){accessExpanded ? " ▾" : " ▸"}
            </Text>
          </Pressable>
          {accessExpanded ? (
            <View style={{ gap: 6 }}>
              {accessGrants.map((g) => {
                const isOwnerRow = g.subject === identityRef;
                const key = `${g.subject}:${g.action}`;
                const revokeKey = `revokeAccess:${g.subject}:${g.action}`;
                return (
                  <View
                    key={key}
                    style={{
                      flexDirection: "row",
                      justifyContent: "space-between",
                      alignItems: "center",
                      borderWidth: 1,
                      borderColor: "#ddd",
                      borderRadius: 8,
                      padding: 10,
                    }}
                  >
                    <View style={{ gap: 2 }}>
                      <Text style={{ fontWeight: "600" }}>{isOwnerRow ? "You (owner)" : g.subject}</Text>
                      <Text style={{ color: "#666" }}>
                        {describePermissionAction(g.action)} · granted {formatUnixSeconds(g.grantedAtUnix)}
                      </Text>
                    </View>
                    {isOwnerRow ? null : (
                      <Pressable disabled={busyAction === revokeKey} onPress={() => handleRevokeAccess(g.subject, g.action)}>
                        <Text style={{ color: "#b00020", textDecorationLine: "underline" }}>
                          {busyAction === revokeKey ? "Revoking…" : "Revoke"}
                        </Text>
                      </Pressable>
                    )}
                  </View>
                );
              })}
            </View>
          ) : null}
        </View>
      ) : null}

      <View style={{ gap: 8 }}>
        <Text style={{ fontSize: 16, fontWeight: "600" }}>History</Text>
        {timeline.length === 0 ? <Text style={{ color: "#666" }}>No history yet.</Text> : null}
        {timeline.map((entry) => (
          <View key={entry.eventId} style={{ borderWidth: 1, borderColor: "#ddd", borderRadius: 8, padding: 10, gap: 2 }}>
            <Text style={{ fontWeight: "600" }}>{describeAction(entry.action)}</Text>
            <Text style={{ color: "#666" }}>
              {formatUnixSeconds(entry.occurredAtUnix)} · {entry.actor}
            </Text>
            {entry.linkedVersion ? (
              <Pressable
                disabled={busyAction === `open:${entry.linkedVersion.versionRef}`}
                onPress={() =>
                  handleOpenVersion(
                    entry.linkedVersion!.versionRef,
                    `Version from ${formatUnixSeconds(entry.linkedVersion!.createdAtUnix)}`,
                  )
                }
              >
                <Text style={{ textDecorationLine: "underline" }}>
                  {busyAction === `open:${entry.linkedVersion.versionRef}` ? "Opening…" : "View this version"}
                </Text>
              </Pressable>
            ) : null}
          </View>
        ))}
      </View>

      {content ? (
        <View style={{ borderWidth: 1, borderColor: "#333", borderRadius: 8, padding: 12, gap: 8 }}>
          <Text style={{ fontWeight: "600" }}>{content.title}</Text>
          <Text selectable style={{ fontFamily: "monospace", fontSize: 12 }}>
            {content.text}
          </Text>
          <Pressable onPress={() => setContent(null)}>
            <Text style={{ textDecorationLine: "underline" }}>Close</Text>
          </Pressable>
        </View>
      ) : null}

      {exportText ? (
        <View style={{ borderWidth: 1, borderColor: "#333", borderRadius: 8, padding: 12, gap: 8 }}>
          <Text style={{ fontWeight: "600" }}>{exportText.title}</Text>
          <Text selectable style={{ fontFamily: "monospace", fontSize: 12 }}>
            {exportText.text}
          </Text>
          <Pressable onPress={() => setExportText(null)}>
            <Text style={{ textDecorationLine: "underline" }}>Close</Text>
          </Pressable>
        </View>
      ) : null}
    </ScrollView>
  );
}

function formatBytes(size: number): string {
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  return `${(size / (1024 * 1024)).toFixed(1)} MB`;
}

/**
 * Best-effort display of arbitrary file bytes: text-ish MIME types decode
 * as UTF-8; anything else (or a decode that turns out not to look like
 * text) falls back to a byte-count summary rather than dumping raw binary
 * into a Text component. This is a display convenience only — GetFileContent
 * itself already returned the real bytes to this screen's caller; no
 * capability decision is made here.
 */
function decodeForDisplay(content: Uint8Array, mimeType?: string): string {
  const looksTextual = !mimeType || mimeType.startsWith("text/") || mimeType === "application/json";
  if (looksTextual) {
    try {
      return new TextDecoder("utf-8", { fatal: true }).decode(content);
    } catch {
      // fall through to byte-count summary
    }
  }
  return `(${content.byteLength} bytes, ${mimeType || "unknown type"} — not displayed as text)`;
}
