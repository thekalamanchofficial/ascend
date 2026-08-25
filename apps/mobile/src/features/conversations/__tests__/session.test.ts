// Unit coverage for the session-establishment orchestration (session.ts) —
// the highest-risk new code in this pass, per the task brief. Mocks the
// crypto/identity/conversations capability clients (module-level jest.mock,
// affecting every importer within this test run, including
// prekeyLifecycle.ts's own imports of the same two modules) and verifies
// the send/receive state machine's four required behaviors:
//
//   1. First message in a conversation: establishes a session (resolveIdentity
//      -> fetchPrekeyBundle -> deriveSharedSecret -> encryptMessage ->
//      createConversation -> sendMessage) and caches the resulting handle.
//   2. Subsequent message (session already cached): reuses the cached
//      handle directly (encryptMessage -> sendMessage), no session
//      establishment machinery invoked again.
//   3. Receiving a message WITH a session_establishment_payload and no
//      cached session: completes (completeSharedSecret), caches the
//      resulting handle, decrypts.
//   4. Receiving a message with NO cached session and NO payload: fails
//      gracefully (a distinct, non-throwing "undecryptable" result), never
//      a crash.
//
// localStore.ts/history.ts are NOT mocked — they go through the real
// Cryptography & Keys secureLocalStore/secureLocalRetrieve, which is itself
// backed by the automatically-applied `expo-secure-store` Jest manual mock
// (apps/mobile/__mocks__/expo-secure-store.ts) — this lets assertions on
// actual persisted state (the whole point of this pass's §4 requirement) run
// for real rather than being mocked away.
import { sendMessage, syncThreadHistory, RecipientNotSetUpError } from "../session";
import { getCachedSessionHandle } from "../localStore";
import { loadHistory } from "../history";
import type { ConversationMessage } from "../../../capabilities/conversations";

jest.mock("../../../capabilities/crypto", () => ({
  deriveSharedSecret: jest.fn(),
  completeSharedSecret: jest.fn(),
  encryptMessage: jest.fn(),
  decryptMessage: jest.fn(),
  generatePrekeyBundle: jest.fn(),
}));
jest.mock("../../../capabilities/identity", () => ({
  resolveIdentity: jest.fn(),
  fetchPrekeyBundle: jest.fn(),
  publishPrekeyBundle: jest.fn(),
}));
jest.mock("../../../capabilities/conversations", () => ({
  createConversation: jest.fn(),
  sendMessage: jest.fn(),
  listMessages: jest.fn(),
}));

import * as crypto from "../../../capabilities/crypto";
import * as identity from "../../../capabilities/identity";
import * as conversationsApi from "../../../capabilities/conversations";

const mockCrypto = crypto as jest.Mocked<typeof crypto>;
const mockIdentity = identity as jest.Mocked<typeof identity>;
const mockConversations = conversationsApi as jest.Mocked<typeof conversationsApi>;

const ME = "identity-me";
const OTHER = "identity-other";
const MY_DEVICE_ID = "device-me";
const MY_HANDLE = { handle: "key_me" };
const SESSION_TOKEN = "session-token";

function bytes(label: string, len = 32): Uint8Array {
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) out[i] = (label.charCodeAt(i % label.length) + i) % 256;
  return out;
}

const SIGNATURE = bytes("sig", 64);

function freshBundleResponse() {
  return {
    status: "PREKEY_BUNDLE_STATUS_AVAILABLE" as const,
    identityDhPublicKey: bytes("their-dh"),
    deviceId: "device-other",
    signedPrekey: { prekeyId: "spk-1", publicKey: bytes("spk-pub"), signature: SIGNATURE, createdAtUnix: 1000 },
    oneTimePrekey: { prekeyId: "otp-1", publicKey: bytes("otp-pub") },
    identitySigningPublicKey: bytes("their-signing"),
    identityDhPublicKeySignature: SIGNATURE,
  };
}

beforeEach(() => {
  jest.clearAllMocks();
  // Reset the mocked expo-secure-store's in-memory backing between tests so
  // localStore.ts/history.ts state doesn't leak across test cases.
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const secureStoreMock = require("expo-secure-store");
  if (typeof secureStoreMock.__reset === "function") secureStoreMock.__reset();

  mockIdentity.resolveIdentity.mockResolvedValue({
    publicIdentity: {
      identityRef: OTHER,
      displayName: "Other",
      publicKey: bytes("their-signing"),
      deviceCount: 1,
      epoch: 0,
    },
  });
  mockCrypto.generatePrekeyBundle.mockResolvedValue({
    identityDhPublicKey: bytes("my-dh"),
    identityDhPublicKeySignature: SIGNATURE,
    signedPrekey: { prekeyId: "my-spk-1", publicKey: bytes("my-spk-pub"), signature: SIGNATURE, createdAtUnix: 999 },
    oneTimePrekeys: [],
  });
  mockIdentity.publishPrekeyBundle.mockResolvedValue({ publishedCount: 0 });
});

describe("sendMessage — first message in a conversation (no cached session)", () => {
  it("establishes a session, sends, and caches the resulting handle", async () => {
    mockIdentity.fetchPrekeyBundle.mockResolvedValue(freshBundleResponse());
    mockCrypto.deriveSharedSecret.mockResolvedValue({
      sharedSecretHandle: { handle: "ratchet_abc" },
      myEphemeralPublicKey: bytes("my-ephemeral"),
    });
    mockCrypto.encryptMessage.mockResolvedValue({ ciphertext: bytes("ciphertext", 40) });
    mockConversations.createConversation.mockResolvedValue({ conversationId: "conv-1", createdAtUnix: 1234 });
    mockConversations.sendMessage.mockResolvedValue({ messageId: "msg-1", sentAtUnix: 1235 });

    const result = await sendMessage({
      me: ME,
      myDeviceId: MY_DEVICE_ID,
      myPrivateKeyHandle: MY_HANDLE,
      otherParticipant: OTHER,
      plaintext: "hello there",
      sessionToken: SESSION_TOKEN,
    });

    expect(result).toEqual({ conversationId: "conv-1", messageId: "msg-1", sentAtUnix: 1235 });

    // The full establishment sequence ran, in order.
    expect(mockIdentity.resolveIdentity).toHaveBeenCalledWith({ identityRef: OTHER });
    expect(mockIdentity.fetchPrekeyBundle).toHaveBeenCalledWith({ identityRef: OTHER }, SESSION_TOKEN);
    expect(mockCrypto.deriveSharedSecret).toHaveBeenCalledTimes(1);
    const deriveArg = mockCrypto.deriveSharedSecret.mock.calls[0][0];
    expect(deriveArg.privateKeyHandle).toEqual(MY_HANDLE);
    expect(deriveArg.theirPrekeyBundle.signedPrekey.prekeyId).toBe("spk-1");

    // createConversation called with no prior conversationId, THEN sendMessage.
    expect(mockConversations.createConversation).toHaveBeenCalledWith(
      { creator: ME, participant: OTHER },
      SESSION_TOKEN,
    );
    expect(mockConversations.sendMessage).toHaveBeenCalledTimes(1);
    const sendArg = mockConversations.sendMessage.mock.calls[0][0];
    expect(sendArg.conversationId).toBe("conv-1");
    expect(sendArg.sender).toBe(ME);
    expect(sendArg.sessionEstablishmentPayload).toBeInstanceOf(Uint8Array);
    expect(sendArg.sessionEstablishmentPayload!.length).toBeGreaterThan(0);

    // The resulting shared_secret_handle is durably cached, keyed by the
    // real (server-assigned) conversationId — required per this pass's §4.
    const cached = await getCachedSessionHandle("conv-1");
    expect(cached).toEqual({ handle: "ratchet_abc" });

    // Local plaintext history was written at send time.
    const history = await loadHistory("conv-1");
    expect(history).toEqual([
      { messageId: "msg-1", sender: ME, sentAtUnix: 1235, direction: "sent", plaintext: "hello there", undecryptable: false },
    ]);
  });

  it("surfaces RecipientNotSetUpError when the recipient has no published bundle, without attempting anything else", async () => {
    mockIdentity.fetchPrekeyBundle.mockResolvedValue({
      status: "PREKEY_BUNDLE_STATUS_NOT_PUBLISHED",
      identityDhPublicKey: new Uint8Array(0),
      deviceId: "",
      signedPrekey: { prekeyId: "", publicKey: new Uint8Array(0), signature: new Uint8Array(0), createdAtUnix: 0 },
      identitySigningPublicKey: new Uint8Array(0),
      identityDhPublicKeySignature: new Uint8Array(0),
    });

    await expect(
      sendMessage({
        me: ME,
        myDeviceId: MY_DEVICE_ID,
        myPrivateKeyHandle: MY_HANDLE,
        otherParticipant: OTHER,
        plaintext: "hi",
        sessionToken: SESSION_TOKEN,
      }),
    ).rejects.toBeInstanceOf(RecipientNotSetUpError);

    expect(mockCrypto.deriveSharedSecret).not.toHaveBeenCalled();
    expect(mockConversations.createConversation).not.toHaveBeenCalled();
    expect(mockConversations.sendMessage).not.toHaveBeenCalled();
  });
});

describe("sendMessage — subsequent message (session already cached)", () => {
  it("reuses the cached handle directly, skipping establishment entirely", async () => {
    mockIdentity.fetchPrekeyBundle.mockResolvedValue(freshBundleResponse());
    mockCrypto.deriveSharedSecret.mockResolvedValue({
      sharedSecretHandle: { handle: "ratchet_abc" },
      myEphemeralPublicKey: bytes("my-ephemeral"),
    });
    mockCrypto.encryptMessage.mockResolvedValue({ ciphertext: bytes("ciphertext1", 40) });
    mockConversations.createConversation.mockResolvedValue({ conversationId: "conv-1", createdAtUnix: 1234 });
    mockConversations.sendMessage.mockResolvedValue({ messageId: "msg-1", sentAtUnix: 1235 });

    await sendMessage({
      me: ME,
      myDeviceId: MY_DEVICE_ID,
      myPrivateKeyHandle: MY_HANDLE,
      otherParticipant: OTHER,
      plaintext: "first",
      sessionToken: SESSION_TOKEN,
    });

    jest.clearAllMocks();
    mockCrypto.encryptMessage.mockResolvedValue({ ciphertext: bytes("ciphertext2", 40) });
    mockConversations.sendMessage.mockResolvedValue({ messageId: "msg-2", sentAtUnix: 1236 });

    const result = await sendMessage({
      me: ME,
      myDeviceId: MY_DEVICE_ID,
      myPrivateKeyHandle: MY_HANDLE,
      otherParticipant: OTHER,
      conversationId: "conv-1",
      plaintext: "second",
      sessionToken: SESSION_TOKEN,
    });

    expect(result).toEqual({ conversationId: "conv-1", messageId: "msg-2", sentAtUnix: 1236 });

    // No re-establishment machinery invoked the second time.
    expect(mockIdentity.resolveIdentity).not.toHaveBeenCalled();
    expect(mockIdentity.fetchPrekeyBundle).not.toHaveBeenCalled();
    expect(mockCrypto.deriveSharedSecret).not.toHaveBeenCalled();
    expect(mockConversations.createConversation).not.toHaveBeenCalled();

    // encryptMessage used the SAME cached handle.
    expect(mockCrypto.encryptMessage).toHaveBeenCalledWith(
      expect.objectContaining({ sharedSecretHandle: { handle: "ratchet_abc" } }),
    );
    const sendArg = mockConversations.sendMessage.mock.calls[0][0];
    expect(sendArg.sessionEstablishmentPayload).toBeUndefined();
  });
});

describe("syncThreadHistory — receiving messages", () => {
  it("completes a session from a session_establishment_payload when none is cached, caches it, and decrypts", async () => {
    const { encodeSessionEstablishmentPayload } = require("../../../capabilities/conversations/sessionPayload");
    const payload = encodeSessionEstablishmentPayload({
      ephemeralPublicKey: bytes("their-ephemeral"),
      identityDhPublicKey: bytes("their-dh"),
      identityDhPublicKeySignature: SIGNATURE,
      signedPrekeyId: "my-spk-1",
      oneTimePrekeyId: "my-otp-1",
    });

    const incoming: ConversationMessage = {
      messageId: "msg-in-1",
      sender: OTHER,
      ciphertext: bytes("incoming-ciphertext", 40),
      sessionEstablishmentPayload: payload,
      sentAtUnix: 5000,
    };
    mockConversations.listMessages.mockResolvedValue({ messages: [incoming], hasMore: false });
    mockCrypto.completeSharedSecret.mockResolvedValue({ sharedSecretHandle: { handle: "ratchet_xyz" } });
    mockCrypto.decryptMessage.mockResolvedValue({ plaintext: new TextEncoder().encode("hi back") });

    const rows = await syncThreadHistory({
      me: ME,
      myPrivateKeyHandle: MY_HANDLE,
      conversationId: "conv-2",
      sessionToken: SESSION_TOKEN,
    });

    expect(rows).toEqual([
      { messageId: "msg-in-1", sender: OTHER, sentAtUnix: 5000, direction: "received", plaintext: "hi back", undecryptable: false },
    ]);

    const completeArg = mockCrypto.completeSharedSecret.mock.calls[0][0];
    expect(completeArg.mySignedPrekeyId).toBe("my-spk-1");
    expect(completeArg.myOneTimePrekeyId).toBe("my-otp-1");
    expect(completeArg.privateKeyHandle).toEqual(MY_HANDLE);

    const cached = await getCachedSessionHandle("conv-2");
    expect(cached).toEqual({ handle: "ratchet_xyz" });
  });

  it("fails gracefully — never throws — when no session is cached AND no payload is present", async () => {
    const incoming: ConversationMessage = {
      messageId: "msg-in-2",
      sender: OTHER,
      ciphertext: bytes("orphan-ciphertext", 40),
      sentAtUnix: 6000,
    };
    mockConversations.listMessages.mockResolvedValue({ messages: [incoming], hasMore: false });

    const rows = await syncThreadHistory({
      me: ME,
      myPrivateKeyHandle: MY_HANDLE,
      conversationId: "conv-3",
      sessionToken: SESSION_TOKEN,
    });

    expect(rows).toEqual([
      { messageId: "msg-in-2", sender: OTHER, sentAtUnix: 6000, direction: "received", plaintext: null, undecryptable: true },
    ]);
    expect(mockCrypto.completeSharedSecret).not.toHaveBeenCalled();
    expect(mockCrypto.decryptMessage).not.toHaveBeenCalled();
  });

  it("reuses an already-cached session for a subsequent received message, ignoring any stray payload", async () => {
    // Pre-seed a cached session the way sendMessage's own first-message path would.
    const { setCachedSessionHandle } = require("../localStore");
    await setCachedSessionHandle("conv-4", { handle: "ratchet_precached" });

    const incoming: ConversationMessage = {
      messageId: "msg-in-3",
      sender: OTHER,
      ciphertext: bytes("second-incoming", 40),
      sentAtUnix: 7000,
    };
    mockConversations.listMessages.mockResolvedValue({ messages: [incoming], hasMore: false });
    mockCrypto.decryptMessage.mockResolvedValue({ plaintext: new TextEncoder().encode("second message") });

    const rows = await syncThreadHistory({
      me: ME,
      myPrivateKeyHandle: MY_HANDLE,
      conversationId: "conv-4",
      sessionToken: SESSION_TOKEN,
    });

    expect(rows[0]).toEqual({
      messageId: "msg-in-3",
      sender: OTHER,
      sentAtUnix: 7000,
      direction: "received",
      plaintext: "second message",
      undecryptable: false,
    });
    expect(mockCrypto.completeSharedSecret).not.toHaveBeenCalled();
    expect(mockCrypto.decryptMessage).toHaveBeenCalledWith(
      expect.objectContaining({ sharedSecretHandle: { handle: "ratchet_precached" } }),
    );
  });

  it("never re-attempts decryption for an already-locally-known message (exactly-once decrypt discipline)", async () => {
    const { appendRows } = require("../history");
    await appendRows("conv-5", [
      { messageId: "msg-known", sender: OTHER, sentAtUnix: 8000, direction: "received", plaintext: "already decrypted", undecryptable: false },
    ]);

    const incoming: ConversationMessage = {
      messageId: "msg-known",
      sender: OTHER,
      ciphertext: bytes("would-fail-if-retried", 40),
      sentAtUnix: 8000,
    };
    mockConversations.listMessages.mockResolvedValue({ messages: [incoming], hasMore: false });

    const rows = await syncThreadHistory({
      me: ME,
      myPrivateKeyHandle: MY_HANDLE,
      conversationId: "conv-5",
      sessionToken: SESSION_TOKEN,
    });

    expect(rows).toHaveLength(1);
    expect(rows[0].plaintext).toBe("already decrypted");
    expect(mockCrypto.decryptMessage).not.toHaveBeenCalled();
    expect(mockCrypto.completeSharedSecret).not.toHaveBeenCalled();
  });

  it("never attempts to decrypt this device's own sent message that is missing from local history", async () => {
    const incoming: ConversationMessage = {
      messageId: "msg-self-missing",
      sender: ME,
      ciphertext: bytes("self-sent-elsewhere", 40),
      sentAtUnix: 9000,
    };
    mockConversations.listMessages.mockResolvedValue({ messages: [incoming], hasMore: false });

    const rows = await syncThreadHistory({
      me: ME,
      myPrivateKeyHandle: MY_HANDLE,
      conversationId: "conv-6",
      sessionToken: SESSION_TOKEN,
    });

    expect(rows).toEqual([
      { messageId: "msg-self-missing", sender: ME, sentAtUnix: 9000, direction: "sent", plaintext: null, undecryptable: true },
    ]);
    expect(mockCrypto.decryptMessage).not.toHaveBeenCalled();
  });
});
