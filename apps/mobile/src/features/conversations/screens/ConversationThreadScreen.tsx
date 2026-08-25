// Conversation thread — ListMessages (via session.syncThreadHistory's full
// backward-pagination reassembly, see that function's own doc comment for
// why decrypt order must exactly match send order) + compose box.
//
// CreateConversation is called LAZILY, only at the moment of actually
// sending the first real message (charter §5, binding) — this screen's
// `conversationId` route param is often undefined (reached via
// StartConversationScreen) and this screen never calls CreateConversation
// or ListMessages itself merely because it was opened; only tapping Send
// does, via session.sendMessage, which composes CreateConversation (if
// needed) + SendMessage behind one user-perceived action.
//
// A message that fails to decrypt renders as a distinct, clearly-labeled
// "can't be decrypted" row — never a crash, never blank (this pass's brief
// §6; the underlying reason is documented in history.ts's header comment:
// decrypt is a one-way, non-replayable ratchet advance).
//
// PASSIVE KEY-ROTATION INDICATOR — SCOPE DECISION (named explicitly,
// per this pass's brief): cryptography-and-keys.charter.md §5/§6 commits to
// "a passive, discoverable indicator... never an interrupting modal" for
// key rotation, with TWO named trigger conditions: (1) a contact's
// identity-signing key changing since last seen, and (2) a session
// established via the exhaustion-fallback (no one-time prekey available)
// path. This screen implements ONLY trigger (1) — ResolveIdentity's
// existing response (identity.PublicIdentity.publicKey) is genuinely
// sufficient data for it (see keyChangeIndicator.ts). Trigger (2) is NOT
// implemented here: crypto.completeSharedSecret's own
// `session_established_signed_prekey_only` audit event fires inside the
// crypto module's own audit stream, with no return value or other frozen-
// contract surface exposing "was a one-time prekey used" back to this
// caller — building that would mean either changing crypto's frozen RPC
// response shape (a charter amendment, out of scope here) or reaching into
// crypto's internals (an Art. 10 violation). Named as a follow-up in this
// pass's report, not silently dropped.
import * as React from "react";
import { View, Text, TextInput, Pressable, ActivityIndicator, ScrollView, FlatList } from "react-native";
import { useNavigation, useRoute } from "@react-navigation/native";
import type { RouteProp } from "@react-navigation/native";
import type { RootStackParamList, NativeStackNavigationProp } from "../../../navigation/types";
import * as conversationsApi from "../../../capabilities/conversations";
import * as identity from "../../../capabilities/identity";
import { sendMessage as sendMessageOrchestration, syncThreadHistory, RecipientNotSetUpError } from "../session";
import { loadHistory, buildLocalTranscriptExport } from "../history";
import type { LocalMessageRow } from "../history";
import { checkAndRecordIdentityKeyChange } from "../keyChangeIndicator";
import { saveAndShareExport } from "../../../lib/export";

type ConversationThreadRouteProp = RouteProp<RootStackParamList, "ConversationThread">;

function formatUnixSeconds(unixSeconds: number): string {
  if (!unixSeconds) return "—";
  return new Date(unixSeconds * 1000).toLocaleString();
}

export function ConversationThreadScreen() {
  const navigation = useNavigation<NativeStackNavigationProp>();
  const route = useRoute<ConversationThreadRouteProp>();
  const { identityRef, deviceId, sessionToken, privateKeyHandle, otherParticipant } = route.params;

  const [conversationId, setConversationId] = React.useState<string | undefined>(route.params.conversationId);
  const [rows, setRows] = React.useState<LocalMessageRow[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [sending, setSending] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  const [composeText, setComposeText] = React.useState("");
  const [keyChanged, setKeyChanged] = React.useState(false);
  const [busyAction, setBusyAction] = React.useState<string | null>(null);
  const [rawExportText, setRawExportText] = React.useState<{ title: string; text: string } | null>(null);
  const [confirmingLocalExport, setConfirmingLocalExport] = React.useState(false);
  const [localExportStatus, setLocalExportStatus] = React.useState<string | null>(null);

  const loadThread = React.useCallback(
    async (currentConversationId: string | undefined) => {
      setLoading(true);
      setError(null);
      try {
        if (currentConversationId) {
          const merged = await syncThreadHistory({
            me: identityRef,
            myPrivateKeyHandle: privateKeyHandle,
            conversationId: currentConversationId,
            sessionToken,
          });
          setRows(merged);
        } else {
          // Not-yet-created conversation — nothing to list yet (charter §5):
          // no ListMessages call, no CreateConversation call, just an empty
          // compose view.
          setRows([]);
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
      } finally {
        setLoading(false);
      }
    },
    [identityRef, privateKeyHandle, sessionToken],
  );

  React.useEffect(() => {
    loadThread(conversationId);
  }, [conversationId, loadThread]);

  // Passive key-change check (see this file's own header comment) — a
  // single, cheap, unauthenticated ResolveIdentity call; never blocks
  // sending, never an interrupting modal.
  React.useEffect(() => {
    identity
      .resolveIdentity({ identityRef: otherParticipant })
      .then((resp) => checkAndRecordIdentityKeyChange(otherParticipant, resp.publicIdentity.publicKey))
      .then(setKeyChanged)
      .catch(() => {
        /* best-effort only — never surface this as a blocking error */
      });
  }, [otherParticipant]);

  async function handleSend() {
    const text = composeText.trim();
    if (!text) return;
    setSending(true);
    setError(null);
    try {
      const result = await sendMessageOrchestration({
        me: identityRef,
        myDeviceId: deviceId,
        myPrivateKeyHandle: privateKeyHandle,
        otherParticipant,
        conversationId,
        plaintext: text,
        sessionToken,
      });
      setComposeText("");
      if (!conversationId) setConversationId(result.conversationId);
      setRows(await loadHistory(result.conversationId));
    } catch (err) {
      if (err instanceof RecipientNotSetUpError) {
        setError(err.message);
      } else {
        setError(err instanceof Error ? err.message : String(err));
      }
    } finally {
      setSending(false);
    }
  }

  // Layer ONE (charter §4 Art. 9) — the server's own stored ciphertext
  // bytes. NEVER a decryptability promise — the button copy says so
  // explicitly, so it's never confused with layer two below.
  async function handleExportServerBytes() {
    if (!conversationId) return;
    setBusyAction("exportServer");
    setError(null);
    try {
      const resp = await conversationsApi.exportConversation(
        { conversationId, requestingSubject: identityRef },
        sessionToken,
      );
      setRawExportText({
        title: `Raw server export (${resp.formatVersion}) — ciphertext, not readable as text`,
        text: new TextDecoder().decode(resp.exportBlob),
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusyAction(null);
    }
  }

  // Layer TWO (charter §4 Art. 9, RECOMMENDED) — this device's own
  // already-decrypted local transcript. Requires explicit user confirmation
  // before producing it (mirrors crypto.exportKeyMaterial's
  // user_confirmation gate) — never silent.
  function confirmLocalExport() {
    setConfirmingLocalExport(true);
  }

  async function handleLocalExportConfirmed() {
    setConfirmingLocalExport(false);
    if (!conversationId) return;
    setBusyAction("exportLocal");
    setError(null);
    setLocalExportStatus(null);
    try {
      const { exportBlob, formatVersion } = buildLocalTranscriptExport({
        conversationId,
        otherParticipant,
        rows,
        userConfirmation: true,
      });
      const filename = `ascend-conversation-transcript-${conversationId}.json`;
      const result = await saveAndShareExport(filename, new TextDecoder().decode(exportBlob), "Save your conversation transcript");
      if (result.shared) {
        setLocalExportStatus(`Readable transcript (${formatVersion}) saved as ${filename}.`);
      } else {
        setRawExportText({ title: `Readable transcript (${formatVersion})`, text: result.text });
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusyAction(null);
    }
  }

  return (
    <View style={{ flex: 1, padding: 24, gap: 12 }}>
      <Text style={{ fontSize: 20, fontWeight: "600" }}>{otherParticipant}</Text>

      {keyChanged ? (
        <View style={{ borderWidth: 1, borderColor: "#b06a00", borderRadius: 8, padding: 10 }}>
          <Text style={{ color: "#b06a00" }}>
            This contact's identity key has changed since you last saw it. If you'd like, verify their key fingerprint
            on the Security screen before continuing.
          </Text>
        </View>
      ) : null}

      {error ? <Text style={{ color: "#b00020" }}>{error}</Text> : null}

      {loading ? <ActivityIndicator /> : null}

      {!loading && rows.length === 0 ? (
        <ScrollView contentContainerStyle={{ paddingTop: 12, alignItems: "center", gap: 8 }}>
          <Text style={{ color: "#666" }}>No messages yet. Say hello.</Text>
        </ScrollView>
      ) : (
        <FlatList
          data={rows}
          keyExtractor={(r) => r.messageId}
          contentContainerStyle={{ gap: 8, flexGrow: 1 }}
          renderItem={({ item }) => {
            const mine = item.direction === "sent";
            return (
              <View
                style={{
                  alignSelf: mine ? "flex-end" : "flex-start",
                  maxWidth: "85%",
                  borderWidth: 1,
                  borderColor: item.undecryptable ? "#b00020" : "#ccc",
                  borderRadius: 8,
                  padding: 10,
                  gap: 2,
                }}
              >
                {item.undecryptable ? (
                  <Text style={{ color: "#b00020", fontStyle: "italic" }}>Can't be decrypted on this device</Text>
                ) : (
                  <Text>{item.plaintext}</Text>
                )}
                <Text style={{ color: "#999", fontSize: 12 }}>{formatUnixSeconds(item.sentAtUnix)}</Text>
              </View>
            );
          }}
        />
      )}

      <View style={{ flexDirection: "row", gap: 8, alignItems: "center" }}>
        <TextInput
          value={composeText}
          onChangeText={setComposeText}
          placeholder="Message"
          multiline
          style={{ flex: 1, borderWidth: 1, borderColor: "#999", borderRadius: 6, padding: 10, minHeight: 40 }}
        />
        <Pressable
          disabled={sending || composeText.trim().length === 0}
          onPress={handleSend}
          style={{ backgroundColor: "#111", paddingVertical: 10, paddingHorizontal: 16, borderRadius: 8 }}
        >
          {sending ? <ActivityIndicator color="white" /> : <Text style={{ color: "white", fontWeight: "600" }}>Send</Text>}
        </Pressable>
      </View>

      {conversationId ? (
        <View style={{ flexDirection: "row", gap: 16, justifyContent: "center" }}>
          <Pressable disabled={busyAction === "exportServer"} onPress={handleExportServerBytes}>
            <Text style={{ textDecorationLine: "underline", fontSize: 12 }}>
              {busyAction === "exportServer" ? "Exporting…" : "Export raw (server bytes)"}
            </Text>
          </Pressable>
          <Pressable disabled={busyAction === "exportLocal"} onPress={confirmLocalExport}>
            <Text style={{ textDecorationLine: "underline", fontSize: 12 }}>
              {busyAction === "exportLocal" ? "Exporting…" : "Export readable transcript"}
            </Text>
          </Pressable>
        </View>
      ) : null}

      {confirmingLocalExport ? (
        <View style={{ borderWidth: 1, borderColor: "#333", borderRadius: 8, padding: 12, gap: 8 }}>
          <Text style={{ fontWeight: "600" }}>Export readable transcript?</Text>
          <Text>
            This produces a plaintext copy of every message this device has been able to decrypt, and saves it
            outside the app's encrypted storage. Unlike the raw server export, this one IS a readable, guaranteed
            copy of what you can see here — treat the file accordingly.
          </Text>
          <View style={{ flexDirection: "row", gap: 16 }}>
            <Pressable onPress={handleLocalExportConfirmed}>
              <Text style={{ fontWeight: "600" }}>Yes, export</Text>
            </Pressable>
            <Pressable onPress={() => setConfirmingLocalExport(false)}>
              <Text>Cancel</Text>
            </Pressable>
          </View>
        </View>
      ) : null}

      {localExportStatus ? (
        <View style={{ borderWidth: 1, borderColor: "#333", borderRadius: 8, padding: 12, gap: 8 }}>
          <Text>{localExportStatus}</Text>
          <Pressable onPress={() => setLocalExportStatus(null)}>
            <Text style={{ textDecorationLine: "underline" }}>Close</Text>
          </Pressable>
        </View>
      ) : null}

      {rawExportText ? (
        <ScrollView style={{ maxHeight: 200, borderWidth: 1, borderColor: "#333", borderRadius: 8, padding: 12 }}>
          <Text style={{ fontWeight: "600" }}>{rawExportText.title}</Text>
          <Text selectable style={{ fontFamily: "monospace", fontSize: 11 }}>
            {rawExportText.text}
          </Text>
          <Pressable onPress={() => setRawExportText(null)}>
            <Text style={{ textDecorationLine: "underline" }}>Close</Text>
          </Pressable>
        </ScrollView>
      ) : null}

      <Pressable onPress={() => navigation.goBack()}>
        <Text style={{ textDecorationLine: "underline" }}>Back</Text>
      </Pressable>
    </View>
  );
}
