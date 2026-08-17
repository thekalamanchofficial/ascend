// Share dialog — intentionally the simplest possible UI for this pass
// (task brief, mirroring charter §7's own documented scope exclusion): a
// single "enter an identity_ref" text field calling SetFilePermissions
// with action "fileobjects.read", grant true. No user search/discovery —
// that capability doesn't exist yet (confirmed with the Chief Architect
// this pass; see this pass's decision-log entry). The recipient still has
// to be told the file_object_id out-of-band to open it (charter §7) —
// this screen surfaces that ID plainly so the sharer can copy/relay it.
import * as React from "react";
import { View, Text, TextInput, Pressable, ActivityIndicator, ScrollView } from "react-native";
import { useNavigation, useRoute } from "@react-navigation/native";
import type { RouteProp } from "@react-navigation/native";
import type { RootStackParamList, NativeStackNavigationProp } from "../../../navigation/types";
import * as fileobjects from "../../../capabilities/fileobjects";

type ShareFileRouteProp = RouteProp<RootStackParamList, "ShareFile">;

export function ShareFileScreen() {
  const navigation = useNavigation<NativeStackNavigationProp>();
  const route = useRoute<ShareFileRouteProp>();
  const { identityRef, sessionToken, fileObjectId } = route.params;

  const [subject, setSubject] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  const [shared, setShared] = React.useState<string[]>([]);

  async function handleShare() {
    setError(null);
    const target = subject.trim();
    if (!target) {
      setError("Enter the identity_ref to share with.");
      return;
    }
    setBusy(true);
    try {
      await fileobjects.setFilePermissions(
        {
          fileObjectId,
          requestingSubject: identityRef,
          grant: true,
          subject: target,
          action: "fileobjects.read",
          scope: "full",
        },
        sessionToken,
      );
      setShared((prev) => [...prev, target]);
      setSubject("");
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <ScrollView contentContainerStyle={{ padding: 24, gap: 16 }}>
      <Text style={{ fontSize: 20, fontWeight: "600" }}>Share file</Text>

      <View style={{ borderWidth: 1, borderColor: "#ccc", borderRadius: 8, padding: 12, gap: 4 }}>
        <Text style={{ color: "#666" }}>File ID (share this with the recipient so they can open it):</Text>
        <Text selectable style={{ fontFamily: "monospace" }}>
          {fileObjectId}
        </Text>
      </View>

      <Text style={{ color: "#666" }}>
        There's no user search yet — enter the recipient's identity_ref exactly as they've shared it with you.
      </Text>

      <View style={{ gap: 8 }}>
        <Text>Recipient identity_ref</Text>
        <TextInput
          value={subject}
          onChangeText={setSubject}
          autoCapitalize="none"
          autoCorrect={false}
          placeholder="identity_ref"
          style={{ borderWidth: 1, borderColor: "#999", borderRadius: 6, padding: 10 }}
        />
      </View>

      {error ? <Text style={{ color: "#b00020" }}>{error}</Text> : null}

      <Pressable
        disabled={busy}
        onPress={handleShare}
        style={{ backgroundColor: "#111", padding: 14, borderRadius: 8, alignItems: "center" }}
      >
        {busy ? <ActivityIndicator color="white" /> : <Text style={{ color: "white", fontWeight: "600" }}>Grant read access</Text>}
      </Pressable>

      {shared.length > 0 ? (
        <View style={{ gap: 4 }}>
          <Text style={{ fontWeight: "600" }}>Shared with (this session):</Text>
          {shared.map((s) => (
            <Text key={s}>{s}</Text>
          ))}
        </View>
      ) : null}

      <Pressable onPress={() => navigation.goBack()}>
        <Text style={{ textDecorationLine: "underline" }}>Done</Text>
      </Pressable>
    </ScrollView>
  );
}
