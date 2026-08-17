// Recovery-from-phrase screen — identity.charter.md §3/§7's "all devices
// lost" path. Not one of the two screens the charter's §5 experience
// budget explicitly names (that section describes the FIRST-creation
// screen and the Devices screen) — included anyway because
// restoreIdentityFlow (onboarding.ts) needs a reachable entry point for
// this pass's "mobile client integration" to be genuinely complete, not
// just a callable-but-unreachable function. Kept intentionally minimal.
import * as React from "react";
import { View, Text, TextInput, Pressable, ActivityIndicator, ScrollView } from "react-native";
import { useNavigation } from "@react-navigation/native";
import type { NativeStackNavigationProp } from "../../../navigation/types";
import { restoreIdentityFlow } from "../onboarding";

export function RestoreIdentityScreen() {
  const navigation = useNavigation<NativeStackNavigationProp>();
  const [identityRef, setIdentityRef] = React.useState("");
  const [recoveryPhrase, setRecoveryPhrase] = React.useState("");
  const [deviceName, setDeviceName] = React.useState("");
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  async function handleRestore() {
    setError(null);
    if (!identityRef.trim() || !recoveryPhrase.trim() || !deviceName.trim()) {
      setError("Enter your identity reference, recovery phrase, and a name for this device.");
      return;
    }
    setLoading(true);
    try {
      const restored = await restoreIdentityFlow({
        identityRef: identityRef.trim(),
        recoveryPhrase: recoveryPhrase.trim(),
        deviceName: deviceName.trim(),
      });
      navigation.navigate("Devices", {
        identityRef: restored.identityRef,
        deviceId: restored.deviceId,
        sessionToken: restored.sessionToken,
        displayName: restored.displayName,
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }

  return (
    <ScrollView contentContainerStyle={{ padding: 24, gap: 16 }}>
      <Text style={{ fontSize: 20, fontWeight: "600" }}>Restore your identity</Text>
      <Text>
        Use this only if every device bound to your identity is gone. Your identity reference and recovery phrase
        together re-authorize a brand-new device without needing any existing device.
      </Text>

      <View style={{ gap: 8 }}>
        <Text>Identity reference</Text>
        <TextInput
          value={identityRef}
          onChangeText={setIdentityRef}
          autoCapitalize="none"
          placeholder="the identityRef you recorded at creation"
          style={{ borderWidth: 1, borderColor: "#999", borderRadius: 6, padding: 10 }}
        />
      </View>

      <View style={{ gap: 8 }}>
        <Text>Recovery phrase</Text>
        <TextInput
          value={recoveryPhrase}
          onChangeText={setRecoveryPhrase}
          autoCapitalize="none"
          multiline
          placeholder="24-word recovery phrase"
          style={{ borderWidth: 1, borderColor: "#999", borderRadius: 6, padding: 10, minHeight: 80 }}
        />
      </View>

      <View style={{ gap: 8 }}>
        <Text>This device's name</Text>
        <TextInput
          value={deviceName}
          onChangeText={setDeviceName}
          placeholder="e.g. New Phone"
          style={{ borderWidth: 1, borderColor: "#999", borderRadius: 6, padding: 10 }}
        />
      </View>

      {error ? <Text style={{ color: "#b00020" }}>{error}</Text> : null}

      <Pressable
        disabled={loading}
        onPress={handleRestore}
        style={{ backgroundColor: "#111", padding: 14, borderRadius: 8, alignItems: "center" }}
      >
        {loading ? (
          <ActivityIndicator color="white" />
        ) : (
          <Text style={{ color: "white", fontWeight: "600" }}>Restore identity</Text>
        )}
      </Pressable>

      <Pressable onPress={() => navigation.navigate("CreateIdentity")}>
        <Text style={{ textDecorationLine: "underline" }}>Back</Text>
      </Pressable>
    </ScrollView>
  );
}
