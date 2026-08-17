import { buildBindDeviceMessage } from "../index";

function nulJoin(...parts: string[]): Uint8Array {
  const encoder = new TextEncoder();
  const encoded = parts.map((p) => encoder.encode(p));
  const total = encoded.reduce((sum, e) => sum + e.length, 0) + (encoded.length - 1);
  const out = new Uint8Array(total);
  let offset = 0;
  encoded.forEach((chunk, i) => {
    out.set(chunk, offset);
    offset += chunk.length;
    if (i < encoded.length - 1) {
      out[offset] = 0;
      offset += 1;
    }
  });
  return out;
}

// Byte-exact regression coverage for the wire contract this client must
// match: services/api/internal/identity/sign.go's buildDeviceBindingMessage,
// verified live against the real running server (see
// docs/DECISION_LOG.md, this pass's entry) — this test pins that same
// exact byte layout so a future accidental change here fails loudly rather
// than producing a signature that silently stops verifying server-side.
describe("buildBindDeviceMessage", () => {
  it("matches the exact NUL-separated, domain-prefixed layout Go's buildDeviceBindingMessage produces", () => {
    const identityRef = "identity-abc";
    const devicePublicKey = new Uint8Array([1, 2, 3, 4]);
    const deviceName = "My Phone";
    const epoch = 3;

    const message = buildBindDeviceMessage(identityRef, devicePublicKey, deviceName, epoch);

    // "AQIDBA==" is base64([1,2,3,4]) — matches what
    // services/api/internal/identity/sign.go computes via
    // base64.StdEncoding.EncodeToString(devicePublicKey).
    const expected = nulJoin("ascend.identity.v1.BindDevice", "identity-abc", "AQIDBA==", "My Phone", "3");

    expect(message).toEqual(expected);
  });

  it("produces different messages for different epochs (the anti-replay property)", () => {
    const devicePublicKey = new Uint8Array([1, 2, 3, 4]);
    const messageAtEpoch0 = buildBindDeviceMessage("id", devicePublicKey, "Device", 0);
    const messageAtEpoch1 = buildBindDeviceMessage("id", devicePublicKey, "Device", 1);
    expect(messageAtEpoch0).not.toEqual(messageAtEpoch1);
  });
});
