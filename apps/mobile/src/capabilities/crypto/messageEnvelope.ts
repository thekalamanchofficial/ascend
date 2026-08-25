// EncryptMessage/DecryptMessage's opaque per-message wire envelope — "the
// ongoing-ratchet exposure gap" amendment, added 2026-08-23
// (docs/capabilities/cryptography-and-keys.charter.md §3/§7 item 2).
// Mirrors envelope.ts's own precedent of a self-contained, versioned format
// documented with an exact byte layout; the exact layout itself is an
// implementation-time decision for the capability engineer (charter §7 item
// 2), not charter-mandated byte-for-byte, the same discretion §7 item 1
// already grants the cipher-suite choice. Conversations (and any other
// caller) relays this byte string opaquely and never interprets it —
// no wire-contract change needed on that capability's side (charter §3).
//
// Wire format:
//
//   [1 byte]   version (currently 1)
//   [24 bytes] XChaCha20-Poly1305 nonce — freshly, randomly generated for
//              EVERY EncryptMessage call (charter §3 — required, never
//              derived from sendMessageNumber or any other reused/
//              predictable state; see index.ts's encryptMessage)
//   [4 bytes]  message sequence number (uint32, big-endian) — this
//              message's position in the SENDER's own outgoing chain
//              (`state.sendMessageNumber` at encrypt time, before it
//              advances). Useful to the receiver and for future
//              out-of-order-handling work (charter §7 item 3, unresolved)
//              — this module does not itself enforce or validate ordering.
//   [remaining] AEAD ciphertext + 16-byte Poly1305 tag (XChaCha20-Poly1305)
import { concatBytes } from "./bytes";

const FORMAT_VERSION = 1;
const NONCE_LEN = 24;
const SEQUENCE_LEN = 4;
const HEADER_LEN = 1 + NONCE_LEN + SEQUENCE_LEN;
const MAX_UINT32 = 0xffffffff;

export function encodeMessageEnvelope(nonce: Uint8Array, sequenceNumber: number, ciphertext: Uint8Array): Uint8Array {
  if (nonce.length !== NONCE_LEN) {
    throw new Error(`Message envelope nonce must be ${NONCE_LEN} bytes (XChaCha20-Poly1305).`);
  }
  if (!Number.isInteger(sequenceNumber) || sequenceNumber < 0 || sequenceNumber > MAX_UINT32) {
    throw new Error(`Message sequence number must be a uint32 (got ${sequenceNumber}).`);
  }
  const sequenceBytes = new Uint8Array(SEQUENCE_LEN);
  new DataView(sequenceBytes.buffer).setUint32(0, sequenceNumber, false);
  return concatBytes(new Uint8Array([FORMAT_VERSION]), nonce, sequenceBytes, ciphertext);
}

export interface DecodedMessageEnvelope {
  nonce: Uint8Array;
  sequenceNumber: number;
  ciphertext: Uint8Array;
}

export function decodeMessageEnvelope(envelope: Uint8Array): DecodedMessageEnvelope {
  if (envelope.length < HEADER_LEN) {
    throw new Error("Message envelope is too short to be valid.");
  }
  let offset = 0;
  const version = envelope[offset];
  offset += 1;
  if (version !== FORMAT_VERSION) {
    throw new Error(`Unsupported message envelope format version: ${version}.`);
  }
  const nonce = envelope.slice(offset, offset + NONCE_LEN);
  offset += NONCE_LEN;
  const sequenceBytes = envelope.slice(offset, offset + SEQUENCE_LEN);
  offset += SEQUENCE_LEN;
  const sequenceNumber = new DataView(
    sequenceBytes.buffer,
    sequenceBytes.byteOffset,
    sequenceBytes.byteLength,
  ).getUint32(0, false);
  const ciphertext = envelope.slice(offset);
  return { nonce, sequenceNumber, ciphertext };
}
