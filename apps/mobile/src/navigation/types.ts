// Shared navigation param-list/type definitions. Split out from
// AppNavigator.tsx so screen components can import the navigation prop
// type without creating a circular import (AppNavigator imports the
// screens; screens must not import AppNavigator back).
import type { NavigationProp } from "@react-navigation/native";

export type RootStackParamList = {
  CreateIdentity: undefined;
  RestoreIdentity: undefined;
  Devices: {
    identityRef: string;
    deviceId: string;
    sessionToken: string;
    displayName: string;
    /**
     * This process's own registered Cryptography & Keys identity key handle
     * (purpose "sign:identity") — added for Conversations' mobile client
     * (conversations.charter.md §2/§5), the first screen flow that genuinely
     * needs it. Threaded the same way `sessionToken` already is: obtained
     * once at CreateIdentity/RestoreIdentity time (see
     * features/onboarding/onboarding.ts's `CreateIdentityResult`/
     * `OnboardingResult`) and carried forward through every screen that
     * needs to make a crypto call using this identity's key, starting here.
     * A `KeyHandle` is process-lifetime-scoped by construction
     * (crypto/keyRegistry.ts) — this is NOT a value that survives a cold
     * app restart; see onboarding.ts's own already-disclosed "KNOWN GAP"
     * comment on persistent login, which this addition does not attempt to
     * solve (out of scope for Conversations, per this pass's brief).
     */
    privateKeyHandle: { handle: string };
  };
  Files: {
    identityRef: string;
    sessionToken: string;
    displayName: string;
  };
  FileDetail: {
    identityRef: string;
    sessionToken: string;
    fileObjectId: string;
    /**
     * Best-effort display hint carried over from wherever this screen was
     * reached (FilesListScreen's own ListFileObjects result, which does
     * carry `owner`) — GetFileMetadata's frozen response shape (charter §3)
     * has no `owner` field, so a file reached via OpenSharedFileScreen's
     * manual-ID entry has no reliable way to learn it. Never used for any
     * access-control decision (the server is the sole authority on that,
     * per every RPC's own CheckPermission/caller-mismatch checks) — display
     * only.
     */
    knownOwner?: string;
  };
  ShareFile: {
    identityRef: string;
    sessionToken: string;
    fileObjectId: string;
  };
  OpenSharedFile: {
    identityRef: string;
    sessionToken: string;
  };
  Access: {
    identityRef: string;
    sessionToken: string;
    displayName: string;
  };
  Activity: {
    identityRef: string;
    sessionToken: string;
    displayName: string;
  };
  // --- Conversations (conversations.charter.md) ---
  //
  // `deviceId`/`privateKeyHandle` are required on every Conversations
  // screen — session establishment (crypto.deriveSharedSecret/
  // completeSharedSecret) and the invisible prekey-bundle bootstrap
  // (crypto.generatePrekeyBundle -> identity.publishPrekeyBundle,
  // features/conversations/prekeyLifecycle.ts) both need them.
  Conversations: {
    identityRef: string;
    deviceId: string;
    sessionToken: string;
    displayName: string;
    privateKeyHandle: { handle: string };
  };
  ConversationThread: {
    identityRef: string;
    deviceId: string;
    sessionToken: string;
    privateKeyHandle: { handle: string };
    otherParticipant: string;
    /**
     * Omitted for a not-yet-created conversation (reached via
     * StartConversationScreen) — CreateConversation is called lazily, only
     * at the moment of actually sending the first message (charter §5),
     * never merely on opening this screen.
     */
    conversationId?: string;
  };
  StartConversation: {
    identityRef: string;
    deviceId: string;
    sessionToken: string;
    privateKeyHandle: { handle: string };
  };
};

/**
 * Named to read naturally at call sites ("this screen's navigation prop"),
 * even though this project uses the minimal custom SimpleStackNavigator
 * (see ./SimpleStackNavigator.tsx) rather than
 * @react-navigation/native-stack — the navigation prop's shape is
 * identical either way (both are plain @react-navigation/core
 * NavigationProp instances); only the visual transition
 * implementation differs.
 */
export type NativeStackNavigationProp = NavigationProp<RootStackParamList>;
