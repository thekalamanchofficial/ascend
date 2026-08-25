// Start a conversation — paste an identity_ref, tap "Message" -> opens
// ConversationThreadScreen for that (not-yet-created) conversation. Zero-
// config, exactly as simple as File Objects' ShareFileScreen (charter §5's
// explicit bar) — no group setup, no channel configuration. Tapping
// "Message" here does NOT call CreateConversation (charter §5, binding) —
// it only navigates to a compose view; only the act of actually sending a
// message (ConversationThreadScreen) calls CreateConversation, immediately
// followed by SendMessage, both invisible behind one user-perceived "hit
// send" action.
import * as React from "react";
import { View, Text, TextInput, Pressable, ScrollView } from "react-native";
import { useNavigation, useRoute } from "@react-navigation/native";
import type { RouteProp } from "@react-navigation/native";
import type { RootStackParamList, NativeStackNavigationProp } from "../../../navigation/types";

type StartConversationRouteProp = RouteProp<RootStackParamList, "StartConversation">;

export function StartConversationScreen() {
  const navigation = useNavigation<NativeStackNavigationProp>();
  const route = useRoute<StartConversationRouteProp>();
  const { identityRef, deviceId, sessionToken, privateKeyHandle } = route.params;

  const [otherParticipant, setOtherParticipant] = React.useState("");
  const [error, setError] = React.useState<string | null>(null);

  function handleContinue() {
    setError(null);
    const target = otherParticipant.trim();
    if (!target) {
      setError("Enter the identity_ref to message.");
      return;
    }
    if (target === identityRef) {
      setError("You can't start a conversation with yourself.");
      return;
    }
    navigation.navigate("ConversationThread", {
      identityRef,
      deviceId,
      sessionToken,
      privateKeyHandle,
      otherParticipant: target,
      // No conversationId — this conversation may not exist yet at all.
      // ConversationThreadScreen only calls CreateConversation at the
      // moment of actually sending (charter §5).
    });
  }

  return (
    <ScrollView contentContainerStyle={{ padding: 24, gap: 16 }}>
      <Text style={{ fontSize: 20, fontWeight: "600" }}>New message</Text>
      <Text style={{ color: "#666" }}>
        There's no user search yet — enter the recipient's identity_ref exactly as they've shared it with you (the
        same standing limitation File Objects' sharing flow already has).
      </Text>
      <Text style={{ color: "#666" }}>
        Direct messages only — group conversations aren't supported yet.
      </Text>

      <View style={{ gap: 8 }}>
        <Text>Recipient identity_ref</Text>
        <TextInput
          value={otherParticipant}
          onChangeText={setOtherParticipant}
          autoCapitalize="none"
          autoCorrect={false}
          placeholder="identity_ref"
          style={{ borderWidth: 1, borderColor: "#999", borderRadius: 6, padding: 10 }}
        />
      </View>

      {error ? <Text style={{ color: "#b00020" }}>{error}</Text> : null}

      <Pressable
        onPress={handleContinue}
        style={{ backgroundColor: "#111", padding: 14, borderRadius: 8, alignItems: "center" }}
      >
        <Text style={{ color: "white", fontWeight: "600" }}>Message</Text>
      </Pressable>

      <Pressable onPress={() => navigation.goBack()}>
        <Text style={{ textDecorationLine: "underline" }}>Cancel</Text>
      </Pressable>
    </ScrollView>
  );
}
