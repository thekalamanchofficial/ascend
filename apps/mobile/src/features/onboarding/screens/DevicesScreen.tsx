// Devices screen — the one place a user manages device/session state, per
// session-authentication.charter.md §5's "Devices/Sessions composition"
// section (binding on this UI layout, per this pass's brief): "there is no
// separate top-level 'Sessions' screen... its rows stay device-level...
// 'sign out everywhere' is the one exception: a single, clearly-labeled,
// identity-level action... stays on the same screen." A device's row shows
// freshness via last_used_at (Session/Request Authentication's more
// precise timestamp) superseding Identity's own last_seen where available,
// exactly as that section allows ("an implementation choice, not a second
// competing timestamp shown to the user").
import * as React from "react";
import { View, Text, Pressable, ActivityIndicator, ScrollView, Alert } from "react-native";
import { useNavigation, useRoute, CommonActions } from "@react-navigation/native";
import type { RouteProp } from "@react-navigation/native";
import * as FileSystem from "expo-file-system";
import * as Sharing from "expo-sharing";
import type { RootStackParamList, NativeStackNavigationProp } from "../../../navigation/types";
import * as identity from "../../../capabilities/identity";
import * as sessionauth from "../../../capabilities/sessionauth";
import { removeDevice, signOutEverywhere } from "../onboarding";
import type { Device } from "../../../capabilities/identity";
import type { SessionSummary } from "../../../capabilities/sessionauth";

// Art. 9 (export) means a real, durable, usable artifact — not a screen the
// user has to copy-paste or screenshot. Writes the export text to a real
// file in app-private storage, then hands it to the OS share/save sheet
// (the standard Expo pattern for getting a file OUT of a sandboxed app on
// Android/iOS — there is no direct "download to Downloads folder" API)
// so the user picks where it actually lands (Files, Drive, email, etc.).
// Falls back to returning the text unsaved only if sharing is genuinely
// unavailable on this device, so the caller can still show something
// rather than the export silently going nowhere.
async function saveAndShareExport(
  filename: string,
  text: string,
  dialogTitle: string,
): Promise<{ shared: true } | { shared: false; text: string }> {
  const fileUri = `${FileSystem.documentDirectory}${filename}`;
  await FileSystem.writeAsStringAsync(fileUri, text, { encoding: FileSystem.EncodingType.UTF8 });

  if (!(await Sharing.isAvailableAsync())) {
    return { shared: false, text };
  }

  await Sharing.shareAsync(fileUri, { mimeType: "application/json", dialogTitle });
  return { shared: true };
}

type DevicesRouteProp = RouteProp<RootStackParamList, "Devices">;

function formatUnixSeconds(unixSeconds: number): string {
  if (!unixSeconds) return "—";
  return new Date(unixSeconds * 1000).toLocaleString();
}

export function DevicesScreen() {
  const navigation = useNavigation<NativeStackNavigationProp>();
  const route = useRoute<DevicesRouteProp>();
  const { identityRef, deviceId: thisDeviceId, sessionToken, displayName } = route.params;

  const [devices, setDevices] = React.useState<Device[]>([]);
  const [sessions, setSessions] = React.useState<SessionSummary[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState<string | null>(null);
  // Unsaved-fallback text (only ever populated if the OS share sheet is
  // genuinely unavailable — see saveAndShareExport) and a brief status
  // message for the normal, successful-save case.
  const [exportFallback, setExportFallback] = React.useState<{ title: string; text: string } | null>(null);
  const [exportStatus, setExportStatus] = React.useState<string | null>(null);
  const [busyAction, setBusyAction] = React.useState<string | null>(null);

  const load = React.useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [devicesResp, sessionsResp] = await Promise.all([
        identity.listDevices({ identityRef }, sessionToken),
        sessionauth.listActiveSessions(sessionToken),
      ]);
      setDevices(devicesResp.devices);
      setSessions(sessionsResp.sessions);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, [identityRef, sessionToken]);

  React.useEffect(() => {
    load();
  }, [load]);

  const lastUsedByDevice = React.useMemo(() => {
    const map = new Map<string, number>();
    for (const s of sessions) {
      const existing = map.get(s.deviceId) ?? 0;
      if (s.lastUsedAtUnix > existing) map.set(s.deviceId, s.lastUsedAtUnix);
    }
    return map;
  }, [sessions]);

  function confirmRemoveDevice(device: Device) {
    Alert.alert(
      "Remove device",
      `Remove "${device.name}"? This revokes its binding and signs it out of every active session immediately.`,
      [
        { text: "Cancel", style: "cancel" },
        {
          text: "Remove",
          style: "destructive",
          onPress: async () => {
            setBusyAction(`remove:${device.deviceId}`);
            try {
              await removeDevice(identityRef, device.deviceId, sessionToken);
              await load();
            } catch (err) {
              setError(err instanceof Error ? err.message : String(err));
            } finally {
              setBusyAction(null);
            }
          },
        },
      ],
    );
  }

  async function handleExportIdentity() {
    setBusyAction("exportIdentity");
    setExportFallback(null);
    setExportStatus(null);
    try {
      const resp = await identity.exportIdentity({ identityRef }, sessionToken);
      const text = new TextDecoder().decode(resp.exportBlob);
      const filename = `ascend-identity-export-${identityRef}.json`;
      const result = await saveAndShareExport(filename, text, "Save your identity export");
      if (result.shared) {
        setExportStatus(`Identity export (${resp.formatVersion}) saved as ${filename}.`);
      } else {
        setExportFallback({ title: `Identity export (${resp.formatVersion})`, text: result.text });
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusyAction(null);
    }
  }

  async function handleExportSessions() {
    setBusyAction("exportSessions");
    setExportFallback(null);
    setExportStatus(null);
    try {
      const resp = await sessionauth.exportSessions(sessionToken);
      const text = new TextDecoder().decode(resp.exportBlob);
      const filename = `ascend-sessions-export-${identityRef}.json`;
      const result = await saveAndShareExport(filename, text, "Save your sessions export");
      if (result.shared) {
        setExportStatus(`Sessions export (${resp.formatVersion}) saved as ${filename}.`);
      } else {
        setExportFallback({ title: `Sessions export (${resp.formatVersion})`, text: result.text });
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusyAction(null);
    }
  }

  function confirmSignOutEverywhere() {
    Alert.alert("Sign out everywhere", "This revokes every session for your identity, including this one.", [
      { text: "Cancel", style: "cancel" },
      {
        text: "Sign out everywhere",
        style: "destructive",
        onPress: async () => {
          setBusyAction("signOutEverywhere");
          try {
            await signOutEverywhere(sessionToken);
            navigation.dispatch(
              CommonActions.reset({ index: 0, routes: [{ name: "CreateIdentity" }] }),
            );
          } catch (err) {
            setError(err instanceof Error ? err.message : String(err));
            setBusyAction(null);
          }
        },
      },
    ]);
  }

  return (
    <ScrollView contentContainerStyle={{ padding: 24, gap: 16 }}>
      <Text style={{ fontSize: 20, fontWeight: "600" }}>Devices</Text>
      <Text>{displayName}</Text>

      <Pressable
        onPress={() => navigation.navigate("Files", { identityRef, sessionToken, displayName })}
        style={{ borderWidth: 1, borderColor: "#111", padding: 12, borderRadius: 8, alignItems: "center" }}
      >
        <Text>Files</Text>
      </Pressable>

      {loading ? <ActivityIndicator /> : null}
      {error ? <Text style={{ color: "#b00020" }}>{error}</Text> : null}

      {devices.map((device) => {
        const lastUsed = lastUsedByDevice.get(device.deviceId);
        return (
          <View key={device.deviceId} style={{ borderWidth: 1, borderColor: "#ccc", borderRadius: 8, padding: 12, gap: 4 }}>
            <Text style={{ fontWeight: "600" }}>
              {device.name} {device.deviceId === thisDeviceId ? "(this device)" : ""}
            </Text>
            <Text>Added: {formatUnixSeconds(device.addedAtUnix)}</Text>
            <Text>
              Last active: {formatUnixSeconds(lastUsed ?? device.lastSeenUnix)}
              {lastUsed ? "" : " (no active session)"}
            </Text>
            <Pressable
              disabled={busyAction === `remove:${device.deviceId}`}
              onPress={() => confirmRemoveDevice(device)}
              style={{ alignSelf: "flex-start", marginTop: 4 }}
            >
              <Text style={{ color: "#b00020" }}>
                {busyAction === `remove:${device.deviceId}` ? "Removing…" : "Remove device"}
              </Text>
            </Pressable>
          </View>
        );
      })}

      <View style={{ gap: 8, marginTop: 8 }}>
        <Pressable
          disabled={busyAction === "exportIdentity"}
          onPress={handleExportIdentity}
          style={{ borderWidth: 1, borderColor: "#111", padding: 12, borderRadius: 8, alignItems: "center" }}
        >
          <Text>{busyAction === "exportIdentity" ? "Exporting…" : "Export identity"}</Text>
        </Pressable>

        <Pressable
          disabled={busyAction === "exportSessions"}
          onPress={handleExportSessions}
          style={{ borderWidth: 1, borderColor: "#111", padding: 12, borderRadius: 8, alignItems: "center" }}
        >
          <Text>{busyAction === "exportSessions" ? "Exporting…" : "Export sessions"}</Text>
        </Pressable>

        <Pressable
          disabled={busyAction === "signOutEverywhere"}
          onPress={confirmSignOutEverywhere}
          style={{ backgroundColor: "#b00020", padding: 12, borderRadius: 8, alignItems: "center" }}
        >
          <Text style={{ color: "white", fontWeight: "600" }}>
            {busyAction === "signOutEverywhere" ? "Signing out…" : "Sign out everywhere"}
          </Text>
        </Pressable>
      </View>

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
    </ScrollView>
  );
}
