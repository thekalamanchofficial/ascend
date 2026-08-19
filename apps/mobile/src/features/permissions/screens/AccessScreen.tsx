// Access screen — "what can I access" (permissions.charter.md §5's second
// half of "a per-resource 'who has access' view, one tap away" plus "what
// can I access"; the first half — "who has access to THIS resource" — is
// File Objects' own `ListFileAccess`/"who has access" affordance on
// FileDetailScreen.tsx, out of scope here per this pass's brief).
//
// Shows the caller's own ListGrantsForSubject result plainly: this is
// Permissions' own generic view over resource_type/resource_id/action/
// scope/granted_at — it has no knowledge of what a `file_object` (or any
// other resource type) actually is, so this screen does not attempt to
// hydrate a row with, e.g., a file's display name (charter §3; the same
// "shared with me" hydration exclusion File Objects' own charter §3
// already reasons through for the mirror-image case). Zero-config default
// (charter §5): the list just loads, no filtering/configuration step.
import * as React from "react";
import { View, Text, Pressable, ActivityIndicator, ScrollView, FlatList } from "react-native";
import { useRoute } from "@react-navigation/native";
import type { RouteProp } from "@react-navigation/native";
import type { RootStackParamList } from "../../../navigation/types";
import * as permissions from "../../../capabilities/permissions";
import type { Grant } from "../../../capabilities/permissions";
import { saveAndShareExport } from "../../../lib/export";

type AccessRouteProp = RouteProp<RootStackParamList, "Access">;

function formatUnixSeconds(unixSeconds: number): string {
  if (!unixSeconds) return "—";
  return new Date(unixSeconds * 1000).toLocaleString();
}

export function AccessScreen() {
  const route = useRoute<AccessRouteProp>();
  const { identityRef, sessionToken, displayName } = route.params;

  const [grants, setGrants] = React.useState<Grant[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState<string | null>(null);
  const [busyAction, setBusyAction] = React.useState<string | null>(null);
  // Unsaved-fallback text (only ever populated if the OS share sheet is
  // genuinely unavailable — see saveAndShareExport) and a brief status
  // message for the normal, successful-save case. Same pattern as
  // DevicesScreen's identity/session exports.
  const [exportFallback, setExportFallback] = React.useState<{ title: string; text: string } | null>(null);
  const [exportStatus, setExportStatus] = React.useState<string | null>(null);

  const load = React.useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const resp = await permissions.listGrantsForSubject({ subject: identityRef }, sessionToken);
      setGrants(resp.grants);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, [identityRef, sessionToken]);

  React.useEffect(() => {
    load();
  }, [load]);

  async function handleExportPermissions() {
    setBusyAction("exportPermissions");
    setExportFallback(null);
    setExportStatus(null);
    try {
      const resp = await permissions.exportPermissions({ identityRef }, sessionToken);
      const text = new TextDecoder().decode(resp.exportBlob);
      const filename = `ascend-permissions-export-${identityRef}.json`;
      const result = await saveAndShareExport(filename, text, "Save your permissions export");
      if (result.shared) {
        setExportStatus(`Permissions export (${resp.formatVersion}) saved as ${filename}.`);
      } else {
        setExportFallback({ title: `Permissions export (${resp.formatVersion})`, text: result.text });
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusyAction(null);
    }
  }

  return (
    <View style={{ flex: 1, padding: 24, gap: 16 }}>
      <Text style={{ fontSize: 20, fontWeight: "600" }}>What I can access</Text>
      <Text>{displayName}</Text>

      {error ? <Text style={{ color: "#b00020" }}>{error}</Text> : null}

      <Pressable
        disabled={busyAction === "exportPermissions"}
        onPress={handleExportPermissions}
        style={{ backgroundColor: "#111", padding: 14, borderRadius: 8, alignItems: "center" }}
      >
        {busyAction === "exportPermissions" ? (
          <ActivityIndicator color="white" />
        ) : (
          <Text style={{ color: "white", fontWeight: "600" }}>Export my permissions</Text>
        )}
      </Pressable>

      {loading ? <ActivityIndicator /> : null}

      {!loading && grants.length === 0 ? (
        <ScrollView contentContainerStyle={{ paddingTop: 24, alignItems: "center", gap: 8 }}>
          <Text style={{ color: "#666" }}>No access grants yet.</Text>
          <Text style={{ color: "#666", textAlign: "center" }}>
            Resources someone shares with you will show up here.
          </Text>
        </ScrollView>
      ) : (
        <FlatList
          data={grants}
          keyExtractor={(g, i) => `${g.resource.resourceType}:${g.resource.resourceId}:${g.action}:${i}`}
          contentContainerStyle={{ gap: 8 }}
          renderItem={({ item }) => (
            <View style={{ borderWidth: 1, borderColor: "#ccc", borderRadius: 8, padding: 12, gap: 4 }}>
              <Text style={{ fontWeight: "600" }}>
                {item.resource.resourceType}: {item.resource.resourceId}
              </Text>
              <Text style={{ color: "#666" }}>
                {item.action} · scope: {item.scope}
              </Text>
              <Text style={{ color: "#666" }}>Granted by {item.grantor}</Text>
              <Text style={{ color: "#666" }}>Granted {formatUnixSeconds(item.grantedAtUnix)}</Text>
            </View>
          )}
        />
      )}

      {exportStatus ? (
        <View style={{ borderWidth: 1, borderColor: "#333", borderRadius: 8, padding: 12, gap: 8 }}>
          <Text>{exportStatus}</Text>
          <Pressable onPress={() => setExportStatus(null)}>
            <Text style={{ textDecorationLine: "underline" }}>Close</Text>
          </Pressable>
        </View>
      ) : null}

      {exportFallback ? (
        <View style={{ borderWidth: 1, borderColor: "#333", borderRadius: 8, padding: 12, gap: 8 }}>
          <Text style={{ fontWeight: "600" }}>{exportFallback.title}</Text>
          <Text>Saving/sharing isn't available on this device — here's the export text to copy manually.</Text>
          <Text selectable style={{ fontFamily: "monospace", fontSize: 12 }}>
            {exportFallback.text}
          </Text>
          <Pressable onPress={() => setExportFallback(null)}>
            <Text style={{ textDecorationLine: "underline" }}>Close</Text>
          </Pressable>
        </View>
      ) : null}
    </View>
  );
}
