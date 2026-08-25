// Conversations inbox — ListConversations, self-only (charter §3). No
// server-side message preview exists (charter §3) — shows
// otherParticipant/createdAt/lastMessageAt only; a client-side preview from
// locally-cached decrypted history is a documented nice-to-have this pass
// skips (see this pass's report) rather than build half of it.
//
// Required disclosure (charter §5, a concrete, checkable mechanism):
// compares each conversation's createdAtUnix against THIS DEVICE's own
// addedAtUnix (Identity's Device record) — a conversation that predates
// this device being added renders a distinct banner, never the generic
// empty state.
//
// Visual design mirrors FilesListScreen.tsx's exact conventions — plain
// View/Text/Pressable, no design system.
import * as React from "react";
import { View, Text, Pressable, ActivityIndicator, ScrollView, FlatList } from "react-native";
import { useNavigation, useRoute, useFocusEffect } from "@react-navigation/native";
import type { RouteProp } from "@react-navigation/native";
import type { RootStackParamList, NativeStackNavigationProp } from "../../../navigation/types";
import * as conversations from "../../../capabilities/conversations";
import * as identity from "../../../capabilities/identity";
import type { ConversationSummary } from "../../../capabilities/conversations";
import { ensureOwnPrekeyIdentity } from "../prekeyLifecycle";

type ConversationsRouteProp = RouteProp<RootStackParamList, "Conversations">;

function formatUnixSeconds(unixSeconds: number): string {
  if (!unixSeconds) return "—";
  return new Date(unixSeconds * 1000).toLocaleString();
}

export function ConversationsListScreen() {
  const navigation = useNavigation<NativeStackNavigationProp>();
  const route = useRoute<ConversationsRouteProp>();
  const { identityRef, deviceId, sessionToken, displayName, privateKeyHandle } = route.params;

  const [items, setItems] = React.useState<ConversationSummary[]>([]);
  const [thisDeviceAddedAtUnix, setThisDeviceAddedAtUnix] = React.useState<number | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState<string | null>(null);

  const load = React.useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      // Fully invisible per crypto/identity charters §5 — no UI reflects
      // this call happening; idempotent (a same-process no-op after the
      // first successful run — see prekeyLifecycle.ts).
      void ensureOwnPrekeyIdentity({ identityRef, deviceId, sessionToken });

      const [convResp, devicesResp] = await Promise.all([
        conversations.listConversations({ requestingSubject: identityRef }, sessionToken),
        identity.listDevices({ identityRef }, sessionToken),
      ]);
      setItems(convResp.conversations);
      const thisDevice = devicesResp.devices.find((d) => d.deviceId === deviceId);
      setThisDeviceAddedAtUnix(thisDevice ? thisDevice.addedAtUnix : null);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, [identityRef, deviceId, sessionToken]);

  // Reload whenever this screen regains focus (e.g. returning from having
  // just sent a first message) — a real, simple "did anything change"
  // signal without inventing a push/websocket transport (charter §7: "how
  // a client learns a new message arrived... is an implementation-time
  // transport decision, not a charter-level one").
  useFocusEffect(
    React.useCallback(() => {
      load();
    }, [load]),
  );

  return (
    <View style={{ flex: 1, padding: 24, gap: 16 }}>
      <Text style={{ fontSize: 20, fontWeight: "600" }}>Messages</Text>
      <Text>{displayName}</Text>

      {error ? <Text style={{ color: "#b00020" }}>{error}</Text> : null}

      <Pressable
        onPress={() =>
          navigation.navigate("StartConversation", { identityRef, deviceId, sessionToken, privateKeyHandle })
        }
        style={{ backgroundColor: "#111", padding: 14, borderRadius: 8, alignItems: "center" }}
      >
        <Text style={{ color: "white", fontWeight: "600" }}>New message</Text>
      </Pressable>

      {loading ? <ActivityIndicator /> : null}

      {!loading && items.length === 0 ? (
        <ScrollView contentContainerStyle={{ paddingTop: 24, alignItems: "center", gap: 8 }}>
          <Text style={{ color: "#666" }}>No conversations yet.</Text>
          <Text style={{ color: "#666", textAlign: "center" }}>
            Tap "New message" and paste someone's identity_ref to start one.
          </Text>
        </ScrollView>
      ) : (
        <FlatList
          data={items}
          keyExtractor={(c) => c.conversationId}
          contentContainerStyle={{ gap: 8 }}
          renderItem={({ item }) => {
            const predatesThisDevice =
              thisDeviceAddedAtUnix !== null && item.createdAtUnix < thisDeviceAddedAtUnix;
            return (
              <Pressable
                onPress={() =>
                  navigation.navigate("ConversationThread", {
                    identityRef,
                    deviceId,
                    sessionToken,
                    privateKeyHandle,
                    otherParticipant: item.otherParticipant,
                    conversationId: item.conversationId,
                  })
                }
                style={{ borderWidth: 1, borderColor: "#ccc", borderRadius: 8, padding: 12, gap: 4 }}
              >
                <Text style={{ fontWeight: "600" }}>{item.otherParticipant}</Text>
                <Text style={{ color: "#666" }}>Started {formatUnixSeconds(item.createdAtUnix)}</Text>
                <Text style={{ color: "#666" }}>Last message {formatUnixSeconds(item.lastMessageAtUnix)}</Text>
                {predatesThisDevice ? (
                  <Text style={{ color: "#b06a00", fontStyle: "italic" }}>
                    Messages from before this device was added aren't shown here.
                  </Text>
                ) : null}
              </Pressable>
            );
          }}
        />
      )}
    </View>
  );
}
