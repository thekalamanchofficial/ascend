// Small dependency-free byte utilities shared across this capability.
// Kept local (rather than pulling in e.g. Node's Buffer, which isn't
// guaranteed present in a React Native runtime without an extra polyfill)
// so this module has no hidden platform assumptions.

const BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

export function concatBytes(...chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((sum, c) => sum + c.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  // Constant-time-ish comparison: always walk the full length rather than
  // short-circuiting on first mismatch, since this is used to compare
  // recipient-id tags derived from key material.
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

export function bytesToBase64(bytes: Uint8Array): string {
  let result = "";
  let i = 0;
  for (; i + 3 <= bytes.length; i += 3) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    result +=
      BASE64_CHARS[(n >> 18) & 0x3f] +
      BASE64_CHARS[(n >> 12) & 0x3f] +
      BASE64_CHARS[(n >> 6) & 0x3f] +
      BASE64_CHARS[n & 0x3f];
  }
  const remaining = bytes.length - i;
  if (remaining === 1) {
    const n = bytes[i] << 16;
    result += BASE64_CHARS[(n >> 18) & 0x3f] + BASE64_CHARS[(n >> 12) & 0x3f] + "==";
  } else if (remaining === 2) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8);
    result +=
      BASE64_CHARS[(n >> 18) & 0x3f] + BASE64_CHARS[(n >> 12) & 0x3f] + BASE64_CHARS[(n >> 6) & 0x3f] + "=";
  }
  return result;
}

export function base64ToBytes(base64: string): Uint8Array {
  const clean = base64.replace(/=+$/, "");
  const lookup = new Map<string, number>();
  for (let i = 0; i < BASE64_CHARS.length; i++) lookup.set(BASE64_CHARS[i], i);

  const out: number[] = [];
  let buffer = 0;
  let bitsCollected = 0;
  for (const char of clean) {
    const value = lookup.get(char);
    if (value === undefined) continue;
    buffer = (buffer << 6) | value;
    bitsCollected += 6;
    if (bitsCollected >= 8) {
      bitsCollected -= 8;
      out.push((buffer >> bitsCollected) & 0xff);
    }
  }
  return new Uint8Array(out);
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
