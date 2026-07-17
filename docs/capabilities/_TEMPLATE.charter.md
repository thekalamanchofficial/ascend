# Capability Charter: <Capability Name>

> Copy this file to `docs/capabilities/<capability-name>.charter.md` and fill in every section before requesting a guardian gate. Do not skip a section — write "N/A: <reason>" if genuinely inapplicable, and expect the guardians to push back if the reason is weak.

## 1. Name and one-line purpose

## 2. Article 17 answer (asked first)

Does this capability increase the user's ownership of digital communication? State the answer directly — do not proceed to the rest of the charter until this is answered honestly.

## 3. Interface

**Exposes** (what other capabilities/apps can call or consume — this is what gets frozen into `packages/contracts`):

**Consumes** (what other capabilities this depends on, referenced only by their published contracts):

> **On implementation-time scope extensions** (precedent set 2026-07-17, Storage capability): a capability-engineer may, without stopping to ask, extend an *authorization check* to a request field that is **already present in the frozen contract** — e.g. gating an additional RPC on `CheckPermission` using a `requesting_subject` field the `.proto` already carries — provided the extension only *increases* a security/ownership guarantee, is self-flagged explicitly in the decision log as going beyond the charter's literal text (not silently merged as settled fact), and requires no change to the wire contract itself. This is routine engineering judgment, confirmed at the merge gate, not a charter violation. It does **not** license extending the *wire contract* — a new field, a new RPC, a changed message shape — which always requires a Chief Architect amendment before implementation, same as any other contract change. If in doubt which category a change falls into, treat it as a wire-contract change and ask first.

## 4. Constitutional obligations

Which articles does this capability's design have to actively satisfy, and how? Be specific — "satisfies Art. 8" is not sufficient; state what data is collected, why, and what is deliberately not collected.

- Art. 1 (ownership):
- Art. 2 (files first-class, if applicable):
- Art. 5 (explainability / audit events emitted):
- Art. 7 (security never reduces ownership, if applicable):
- Art. 8 (privacy / data manifest — list every field collected and its documented purpose):
- Art. 9 (export path):
- Art. 10 (modularity — dependencies limited to published contracts):
- Other relevant articles:

## 5. Experience budget

What is the cognitive cost this capability adds to the platform's surface? What are the excellent defaults (Art. 13) that make the common case need zero configuration? What is discoverable-but-hidden for power users (Art. 12)?

## 6. Threat model (if the surface touches keys, encryption, permissions, storage boundaries, or export)

Otherwise write "N/A — no security-sensitive surface" and Security Steward gate may be skipped.

## 7. Open questions / risks

## 8. Guardian gate results

Fill in after each guardian reviews. A capability cannot move to `frozen` status in the registry until all applicable gates below are ✅.

| Guardian | Verdict (✅ pass / 🚫 blocked / N/A) | Notes | Date |
|---|---|---|---|
| Constitution Warden | | | |
| Experience Guardian | | | |
| Security Steward | | | |

## 9. Decision log references

Link to `docs/DECISION_LOG.md` entries generated while chartering this capability.
