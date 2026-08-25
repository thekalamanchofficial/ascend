// Single guided create-identity screen — identity.charter.md §5: "a single,
// guided screen shown once ... states plainly in one sentence that losing
// [the recovery phrase] together with all devices means permanent,
// unrecoverable loss of identity, and requires the user to actively
// confirm they've saved it before proceeding — mirroring the seriousness
// of the moment without turning it into a multi-step wizard." Implemented
// as ONE screen with two internal steps (form -> confirm phrase), not two
// navigator routes, per that "not a wizard" instruction.
//
// Visual design is deliberately minimal/functional (plain React Native
// primitives, no styling library) — this pass is about wiring the real
// capabilities together correctly, not visual polish; see this module's
// decision-log entry.
import * as React from "react";
import { View, Text, TextInput, Pressable, ActivityIndicator, ScrollView } from "react-native";
import { useNavigation } from "@react-navigation/native";
import * as Clipboard from "expo-clipboard";
import type { NativeStackNavigationProp } from "../../../navigation/types";
import { createIdentityFlow } from "../onboarding";
import type { CreateIdentityResult } from "../onboarding";

type Step = "form" | "confirmPhrase";

export function CreateIdentityScreen() {
  const navigation = useNavigation<NativeStackNavigationProp>();
  const [step, setStep] = React.useState<Step>("form");
  const [displayName, setDisplayName] = React.useState("");
  const [deviceName, setDeviceName] = React.useState("");
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  const [result, setResult] = React.useState<CreateIdentityResult | null>(null);
  const [confirmedSaved, setConfirmedSaved] = React.useState(false);
  // "Bring your own phrase" — opt-in, off by default (see onboarding.ts's
  // createIdentityFlow doc comment for the full Art. 13/1/6 reasoning). Off
  // by default so the zero-config CSPRNG-generated path remains the thing
  // every user gets unless they deliberately reach for this.
  const [useOwnPhrase, setUseOwnPhrase] = React.useState(false);
  const [ownPhrase, setOwnPhrase] = React.useState("");

  async function handleCreate() {
    setError(null);
    if (!displayName.trim() || !deviceName.trim()) {
      setError("Enter a display name and a name for this device.");
      return;
    }
    if (useOwnPhrase && !ownPhrase.trim()) {
      setError("Enter the recovery phrase you'd like to use, or turn off \"Use my own phrase\".");
      return;
    }
    setLoading(true);
    try {
      const created = await createIdentityFlow({
        displayName: displayName.trim(),
        firstDeviceName: deviceName.trim(),
        customRecoveryPhrase: useOwnPhrase ? ownPhrase.trim() : undefined,
      });
      setResult(created);
      setStep("confirmPhrase");
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }

  async function handlePasteOwnPhrase() {
    const text = await Clipboard.getStringAsync();
    if (text) setOwnPhrase(text);
  }

  function handleContinue() {
    if (!result) return;
    navigation.navigate("Devices", {
      identityRef: result.identityRef,
      deviceId: result.deviceId,
      sessionToken: result.sessionToken,
      displayName: result.displayName,
      privateKeyHandle: result.identityPrivateKeyHandle,
    });
  }

  if (step === "confirmPhrase" && result) {
    return (
      <ScrollView contentContainerStyle={{ padding: 24, gap: 16 }}>
        <Text style={{ fontSize: 20, fontWeight: "600" }}>Save your recovery phrase</Text>
        <Text>
          This is the only way to recover your identity if you lose every device. Write it down and store it
          somewhere safe, separate from your devices.
        </Text>
        <Text style={{ fontWeight: "700" }}>
          If you lose this phrase AND every bound device, your identity is permanently and unrecoverably lost —
          there is no support-mediated recovery.
        </Text>
        <View style={{ padding: 12, borderWidth: 1, borderColor: "#333", borderRadius: 8 }}>
          <Text selectable style={{ fontFamily: "monospace", fontSize: 16 }}>
            {result.recoveryPhrase}
          </Text>
        </View>
        <Pressable
          onPress={() => setConfirmedSaved((v) => !v)}
          style={{ flexDirection: "row", alignItems: "center", gap: 8 }}
        >
          <View
            style={{
              width: 22,
              height: 22,
              borderWidth: 1,
              borderColor: "#333",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            {confirmedSaved ? <Text>✓</Text> : null}
          </View>
          <Text>I have saved this recovery phrase somewhere safe.</Text>
        </Pressable>
        <Pressable
          disabled={!confirmedSaved}
          onPress={handleContinue}
          style={{
            backgroundColor: confirmedSaved ? "#111" : "#999",
            padding: 14,
            borderRadius: 8,
            alignItems: "center",
          }}
        >
          <Text style={{ color: "white", fontWeight: "600" }}>Continue</Text>
        </Pressable>
      </ScrollView>
    );
  }

  return (
    <ScrollView contentContainerStyle={{ padding: 24, gap: 16 }}>
      <Text style={{ fontSize: 20, fontWeight: "600" }}>Create your identity</Text>
      <Text>Your identity and this device's key are generated on-device — nothing here requires a password.</Text>

      <View style={{ gap: 8 }}>
        <Text>Display name</Text>
        <TextInput
          value={displayName}
          onChangeText={setDisplayName}
          placeholder="e.g. Jordan Rivera"
          style={{ borderWidth: 1, borderColor: "#999", borderRadius: 6, padding: 10 }}
        />
      </View>

      <View style={{ gap: 8 }}>
        <Text>This device's name</Text>
        <TextInput
          value={deviceName}
          onChangeText={setDeviceName}
          placeholder="e.g. Jordan's Phone"
          style={{ borderWidth: 1, borderColor: "#999", borderRadius: 6, padding: 10 }}
        />
      </View>

      <Pressable
        onPress={() => setUseOwnPhrase((v) => !v)}
        style={{ flexDirection: "row", alignItems: "center", gap: 8 }}
      >
        <View
          style={{
            width: 22,
            height: 22,
            borderWidth: 1,
            borderColor: "#333",
            alignItems: "center",
            justifyContent: "center",
          }}
        >
          {useOwnPhrase ? <Text>✓</Text> : null}
        </View>
        <Text>Use my own recovery phrase</Text>
      </Pressable>

      {useOwnPhrase ? (
        <View style={{ gap: 8 }}>
          <Text style={{ color: "#b00020" }}>
            Your identity's security depends entirely on this phrase's randomness. Only use a phrase you generated
            with a source you trust (e.g. another BIP-39-compliant wallet or device) — a phrase you made up yourself
            is far weaker than one this app generates for you, and there's no way for Ascend to warn you if it's
            guessable.
          </Text>
          <TextInput
            value={ownPhrase}
            onChangeText={setOwnPhrase}
            autoCapitalize="none"
            multiline
            placeholder="Your own recovery phrase"
            style={{ borderWidth: 1, borderColor: "#999", borderRadius: 6, padding: 10, minHeight: 80 }}
          />
          <Pressable
            onPress={handlePasteOwnPhrase}
            style={{ alignSelf: "flex-start", borderWidth: 1, borderColor: "#999", borderRadius: 6, padding: 8 }}
          >
            <Text>Paste from clipboard</Text>
          </Pressable>
        </View>
      ) : null}

      {error ? <Text style={{ color: "#b00020" }}>{error}</Text> : null}

      <Pressable
        disabled={loading}
        onPress={handleCreate}
        style={{ backgroundColor: "#111", padding: 14, borderRadius: 8, alignItems: "center" }}
      >
        {loading ? <ActivityIndicator color="white" /> : <Text style={{ color: "white", fontWeight: "600" }}>Create identity</Text>}
      </Pressable>

      <Pressable onPress={() => navigation.navigate("RestoreIdentity")}>
        <Text style={{ textDecorationLine: "underline" }}>Already have a recovery phrase? Restore access</Text>
      </Pressable>
    </ScrollView>
  );
}
