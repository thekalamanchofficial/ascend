import { buildIssueSessionMessage } from "../index";

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
// match: services/api/internal/sessionauth/sign.go's
// buildIssueSessionMessage, verified live against the real running server
// (see docs/DECISION_LOG.md, this pass's entry).
describe("buildIssueSessionMessage", () => {
  it("matches the exact NUL-separated, domain-prefixed layout Go's buildIssueSessionMessage produces", () => {
    const message = buildIssueSessionMessage("identity-abc", "device-123", "nonce-xyz");
    const expected = nulJoin("ascend.session.v1.IssueSession", "identity-abc", "device-123", "nonce-xyz");
    expect(message).toEqual(expected);
  });

  it("is distinct from Identity's BindDevice domain-separation prefix (a proof for one operation can never replay as the other)", () => {
    const message = buildIssueSessionMessage("id", "device", "nonce");
    const decoded = new TextDecoder().decode(message);
    expect(decoded.startsWith("ascend.session.v1.IssueSession")).toBe(true);
    expect(decoded.startsWith("ascend.identity.v1.BindDevice")).toBe(false);
  });

  it("produces different messages for different challenge nonces (the anti-replay property)", () => {
    const messageA = buildIssueSessionMessage("id", "device", "nonce-a");
    const messageB = buildIssueSessionMessage("id", "device", "nonce-b");
    expect(messageA).not.toEqual(messageB);
  });
});
