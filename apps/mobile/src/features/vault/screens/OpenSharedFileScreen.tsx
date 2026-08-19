// Open shared file — a manual file_object_id entry field (charter §7's
// documented interim flow: a recipient who doesn't own a file can't
// discover it via ListFileObjects, but can open it directly via
// GetFileContent/GetFileMetadata once they have the ID from the sharer).
// This screen only validates that the ID resolves (a GetFileMetadata
// probe) before navigating to the shared FileDetailScreen — it makes no
// access-control decision itself; a denied/not-found ID surfaces the real
// server error inline.
import * as React from "react";
import { View, Text, TextInput, Pressable, ActivityIndicator, ScrollView } from "react-native";
import { useNavigation, useRoute } from "@react-navigation/native";
import type { RouteProp } from "@react-navigation/native";
import type { RootStackParamList, NativeStackNavigationProp } from "../../../navigation/types";
import * as fileobjects from "../../../capabilities/fileobjects";

type OpenSharedFileRouteProp = RouteProp<RootStackParamList, "OpenSharedFile">;

export function OpenSharedFileScreen() {
  const navigation = useNavigation<NativeStackNavigationProp>();
  const route = useRoute<OpenSharedFileRouteProp>();
  const { identityRef, sessionToken } = route.params;

  const [fileObjectId, setFileObjectId] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  async function handleOpen() {
    setError(null);
    const id = fileObjectId.trim();
    if (!id) {
      setError("Enter the file ID the sharer gave you.");
      return;
    }
    setBusy(true);
    try {
      // Probe first so a bad/unauthorized ID surfaces here, not as a
      // confusing empty detail screen.
      await fileobjects.getFileMetadata({ fileObjectId: id, requestingSubject: identityRef }, sessionToken);
      navigation.navigate("FileDetail", { identityRef, sessionToken, fileObjectId: id });
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <ScrollView contentContainerStyle={{ padding: 24, gap: 16 }}>
      <Text style={{ fontSize: 20, fontWeight: "600" }}>Open a shared file</Text>
      <Text style={{ color: "#666" }}>
        Ask the person who shared it with you for the file ID, then enter it below.
      </Text>

      <View style={{ gap: 8 }}>
        <Text>File ID</Text>
        <TextInput
          value={fileObjectId}
          onChangeText={setFileObjectId}
          autoCapitalize="none"
          autoCorrect={false}
          placeholder="file_object_id"
          style={{ borderWidth: 1, borderColor: "#999", borderRadius: 6, padding: 10 }}
        />
      </View>

      {error ? <Text style={{ color: "#b00020" }}>{error}</Text> : null}

      <Pressable
        disabled={busy}
        onPress={handleOpen}
        style={{ backgroundColor: "#111", padding: 14, borderRadius: 8, alignItems: "center" }}
      >
        {busy ? <ActivityIndicator color="white" /> : <Text style={{ color: "white", fontWeight: "600" }}>Open</Text>}
      </Pressable>
    </ScrollView>
  );
}
