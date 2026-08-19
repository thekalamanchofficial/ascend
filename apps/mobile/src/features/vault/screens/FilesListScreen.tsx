// Files list — "my files" (charter §3's ListFileObjects, self-only).
// Zero-config default (charter §5): the list just loads; "Upload" is a
// single-tap document-picker -> CreateFileObject flow with no extra
// configuration step. Visual design is deliberately minimal/functional,
// same discipline as onboarding's screens.
import * as React from "react";
import { View, Text, Pressable, ActivityIndicator, ScrollView, FlatList } from "react-native";
import { useNavigation, useRoute } from "@react-navigation/native";
import type { RouteProp } from "@react-navigation/native";
import * as DocumentPicker from "expo-document-picker";
import * as FileSystem from "expo-file-system";
import type { RootStackParamList, NativeStackNavigationProp } from "../../../navigation/types";
import * as fileobjects from "../../../capabilities/fileobjects";
import { base64ToBytes } from "../../../capabilities/crypto/bytes";
import type { FileObject } from "../../../capabilities/fileobjects";

type FilesRouteProp = RouteProp<RootStackParamList, "Files">;

function formatUnixSeconds(unixSeconds: number): string {
  if (!unixSeconds) return "—";
  return new Date(unixSeconds * 1000).toLocaleString();
}

function formatBytes(size: number): string {
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  return `${(size / (1024 * 1024)).toFixed(1)} MB`;
}

export function FilesListScreen() {
  const navigation = useNavigation<NativeStackNavigationProp>();
  const route = useRoute<FilesRouteProp>();
  const { identityRef, sessionToken, displayName } = route.params;

  const [files, setFiles] = React.useState<FileObject[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [uploading, setUploading] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  const load = React.useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const resp = await fileobjects.listFileObjects(
        { owner: identityRef, requestingSubject: identityRef },
        sessionToken,
      );
      setFiles(resp.fileObjects);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, [identityRef, sessionToken]);

  React.useEffect(() => {
    load();
  }, [load]);

  async function handleUpload() {
    setError(null);
    const picked = await DocumentPicker.getDocumentAsync({ copyToCacheDirectory: true });
    if (picked.canceled || !picked.assets || picked.assets.length === 0) return;
    const asset = picked.assets[0];

    setUploading(true);
    try {
      const base64Content = await FileSystem.readAsStringAsync(asset.uri, {
        encoding: FileSystem.EncodingType.Base64,
      });
      await fileobjects.createFileObject(
        {
          owner: identityRef,
          requestingSubject: identityRef,
          initialContent: base64ToBytes(base64Content),
          name: asset.name,
          mimeType: asset.mimeType || "application/octet-stream",
        },
        sessionToken,
      );
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setUploading(false);
    }
  }

  return (
    <View style={{ flex: 1, padding: 24, gap: 16 }}>
      <Text style={{ fontSize: 20, fontWeight: "600" }}>Files</Text>
      <Text>{displayName}</Text>

      {error ? <Text style={{ color: "#b00020" }}>{error}</Text> : null}

      <Pressable
        disabled={uploading}
        onPress={handleUpload}
        style={{ backgroundColor: "#111", padding: 14, borderRadius: 8, alignItems: "center" }}
      >
        {uploading ? (
          <ActivityIndicator color="white" />
        ) : (
          <Text style={{ color: "white", fontWeight: "600" }}>Upload a file</Text>
        )}
      </Pressable>

      <Pressable onPress={() => navigation.navigate("OpenSharedFile", { identityRef, sessionToken })}>
        <Text style={{ textDecorationLine: "underline" }}>Open a file shared with me</Text>
      </Pressable>

      {loading ? <ActivityIndicator /> : null}

      {!loading && files.length === 0 ? (
        <ScrollView contentContainerStyle={{ paddingTop: 24, alignItems: "center", gap: 8 }}>
          <Text style={{ color: "#666" }}>No files yet.</Text>
          <Text style={{ color: "#666", textAlign: "center" }}>
            Upload one above — it will automatically get identity, history, and permissions.
          </Text>
        </ScrollView>
      ) : (
        <FlatList
          data={files}
          keyExtractor={(f) => f.fileObjectId}
          contentContainerStyle={{ gap: 8 }}
          renderItem={({ item }) => (
            <Pressable
              onPress={() =>
                navigation.navigate("FileDetail", {
                  identityRef,
                  sessionToken,
                  fileObjectId: item.fileObjectId,
                  knownOwner: item.owner,
                })
              }
              style={{ borderWidth: 1, borderColor: "#ccc", borderRadius: 8, padding: 12, gap: 4 }}
            >
              <Text style={{ fontWeight: "600" }}>{item.name || "(untitled)"}</Text>
              <Text style={{ color: "#666" }}>
                {item.mimeType || "unknown type"} · {formatBytes(item.sizeBytes)}
              </Text>
              <Text style={{ color: "#666" }}>Created {formatUnixSeconds(item.createdAtUnix)}</Text>
              {item.tags.length > 0 ? <Text style={{ color: "#666" }}>Tags: {item.tags.join(", ")}</Text> : null}
            </Pressable>
          )}
        />
      )}
    </View>
  );
}
