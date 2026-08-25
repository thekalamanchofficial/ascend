// session_establishment_payload — the opaque byte envelope this capability's
// `SendMessage.session_establishment_payload` carries (conversations.charter.md
// §3: "opaque bytes... Conversations relays it byte-for-byte without ever
// interpreting it"). This codec is the one place BOTH ends of a real
// Conversations exchange must agree on its shape — defined here (self-
// describing, versioned) rather than ad hoc inline in the feature-
// composition layer, mirroring identity/index.ts's `buildBindDeviceMessage`
// precedent: a capability-specific wire-message construction that belongs
// next to the capability whose wire contract it fills a field on, even
// though its CONTENTS are entirely Cryptography & Keys' key material (this
// module never imports crypto — it only shapes/parses bytes a caller
// already produced/needs).
//
// Required fields, per cryptography-and-keys.charter.md §7 item 4 (matched
// field for field, not a sketch): the initiator's fresh ephemeral public
// key, the initiator's identity_dh_public_key, the initiator's
// identity_dh_public_key_signature, the responder's signed_prekey's
// prekey_id, and the responder's one_time_prekey's prekey_id if one was
// used.
//
// Wire format (mirrors crypto/messageEnvelope.ts's own precedent of a
// self-contained, versioned format with an exact documented byte layout —
// this format is entirely this app's own invention, opaque to Conversations'
// backend, which never parses it; only two mobile clients of this same
// capability need to agree on it):
//
//   [1 byte]    version (currently 1)
//   [32 bytes]  ephemeralPublicKey (X25519)
//   [32 bytes]  identityDhPublicKey (X25519)
//   [64 bytes]  identityDhPublicKeySignature (Ed25519 signature)
//   [1 byte]    signedPrekeyId length N1 (UTF-8 byte length, max 255)
//   [N1 bytes]  signedPrekeyId (UTF-8)
//   [1 byte]    flags — bit 0 set means a oneTimePrekeyId follows
//   [1 byte]    oneTimePrekeyId length N2 — present only if flags bit 0 is set
//   [N2 bytes]  oneTimePrekeyId (UTF-8) — present only if flags bit 0 is set
import { concatBytes } from "../crypto/bytes";

const FORMAT_VERSION = 1;
const EPHEMERAL_KEY_LEN = 32;
const IDENTITY_DH_KEY_LEN = 32;
const IDENTITY_DH_SIGNATURE_LEN = 64;
const ONE_TIME_PREKEY_FLAG = 0b0000_0001;

export interface SessionEstablishmentPayload {
  ephemeralPublicKey: Uint8Array;
  identityDhPublicKey: Uint8Array;
  identityDhPublicKeySignature: Uint8Array;
  signedPrekeyId: string;
  oneTimePrekeyId?: string;
}

function encodeIdString(id: string): Uint8Array {
  const bytes = new TextEncoder().encode(id);
  if (bytes.length > 255) {
    throw new Error(`Prekey id is too long to encode (${bytes.length} bytes, max 255): "${id}".`);
  }
  return concatBytes(new Uint8Array([bytes.length]), bytes);
}

export function encodeSessionEstablishmentPayload(payload: SessionEstablishmentPayload): Uint8Array {
  if (payload.ephemeralPublicKey.length !== EPHEMERAL_KEY_LEN) {
    throw new Error(`ephemeralPublicKey must be ${EPHEMERAL_KEY_LEN} bytes (X25519).`);
  }
  if (payload.identityDhPublicKey.length !== IDENTITY_DH_KEY_LEN) {
    throw new Error(`identityDhPublicKey must be ${IDENTITY_DH_KEY_LEN} bytes (X25519).`);
  }
  if (payload.identityDhPublicKeySignature.length !== IDENTITY_DH_SIGNATURE_LEN) {
    throw new Error(`identityDhPublicKeySignature must be ${IDENTITY_DH_SIGNATURE_LEN} bytes (Ed25519).`);
  }

  const flags = payload.oneTimePrekeyId !== undefined ? ONE_TIME_PREKEY_FLAG : 0;
  const parts = [
    new Uint8Array([FORMAT_VERSION]),
    payload.ephemeralPublicKey,
    payload.identityDhPublicKey,
    payload.identityDhPublicKeySignature,
    encodeIdString(payload.signedPrekeyId),
    new Uint8Array([flags]),
  ];
  if (payload.oneTimePrekeyId !== undefined) {
    parts.push(encodeIdString(payload.oneTimePrekeyId));
  }
  return concatBytes(...parts);
}

export function decodeSessionEstablishmentPayload(bytes: Uint8Array): SessionEstablishmentPayload {
  let offset = 0;

  function readByte(label: string): number {
    if (offset >= bytes.length) throw new Error(`session_establishment_payload is too short to read ${label}.`);
    return bytes[offset++];
  }

  function readFixed(len: number, label: string): Uint8Array {
    if (offset + len > bytes.length) {
      throw new Error(`session_establishment_payload is too short to read ${label} (${len} bytes).`);
    }
    const out = bytes.slice(offset, offset + len);
    offset += len;
    return out;
  }

  function readIdString(label: string): string {
    const len = readByte(`${label} length`);
    const raw = readFixed(len, label);
    return new TextDecoder().decode(raw);
  }

  const version = readByte("version");
  if (version !== FORMAT_VERSION) {
    throw new Error(`Unsupported session_establishment_payload format version: ${version}.`);
  }

  const ephemeralPublicKey = readFixed(EPHEMERAL_KEY_LEN, "ephemeralPublicKey");
  const identityDhPublicKey = readFixed(IDENTITY_DH_KEY_LEN, "identityDhPublicKey");
  const identityDhPublicKeySignature = readFixed(IDENTITY_DH_SIGNATURE_LEN, "identityDhPublicKeySignature");
  const signedPrekeyId = readIdString("signedPrekeyId");
  const flags = readByte("flags");
  const oneTimePrekeyId = flags & ONE_TIME_PREKEY_FLAG ? readIdString("oneTimePrekeyId") : undefined;

  return { ephemeralPublicKey, identityDhPublicKey, identityDhPublicKeySignature, signedPrekeyId, oneTimePrekeyId };
}
