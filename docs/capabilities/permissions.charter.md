# Capability Charter: Permissions

## 1. Name and one-line purpose

**Permissions** — the fine-grained, least-privilege access-control primitive every other capability calls to decide who may do what to which resource.

## 2. Article 17 answer (asked first)

Yes. Ownership includes control over who else can see or act on a user's data. Without a single, trustworthy permission primitive, every capability would reinvent access control inconsistently (violating Art. 16), and users would have no single place to understand or change who can do what (violating Art. 5, 15).

## 3. Interface

**Exposes:**
- `CheckPermission(subject, action, resource) -> allow/deny` — the single call every other capability uses; no capability implements its own parallel access-control logic.
- `GrantPermission(grantor, subject, action, resource, scope)` / `RevokePermission(...)` — explicit rule changes.
- `DefinePolicy(resource_type, default_rules)` — lets a capability register its default (least-privilege) policy shape when it comes online.
- `ListGrants(resource)` / `ListGrants(subject)` — "who can see this" and "what can I access," both needed for Art. 5 explainability.
- `ExportPermissions(identity)` — a user's full grant/revoke history and current effective permissions (Art. 9).

**Consumes:**
- **Identity** — to resolve `subject` references to real, bound identities (published contract only, not Identity's internals).
- **Audit / Explainability** — every grant/revoke emits an audit event; every `CheckPermission` deny *may* optionally surface an explanation on request.

## 4. Constitutional obligations

- **Art. 6 (users define behavior):** permission policies are user-authored rules the platform executes — not hardcoded workflows. A user can express "only people in this conversation can forward files from it" as a policy, not wait for the platform to ship a specific toggle.
- **Art. 7 (least privilege):** every new resource type defaults to the narrowest reasonable grant (typically: owner-only); broadening access is always an explicit, attributable action.
- **Art. 5 (explainability):** every grant and revoke is audited with grantor, subject, action, resource, and timestamp; `ListGrants` lets a user see exactly who has access to their resource right now, not just historically.
- **Art. 8 (privacy) — data manifest:** a grant record stores exactly `grantor`, `subject`, `action`, `resource`, `scope`, and `timestamp`. Purpose of each: `grantor`/`subject`/`action`/`resource` — the minimum needed to answer "who can do what to this" (Art. 5, 15); `scope` — bounds a grant to less than full access where the policy allows (e.g. read-only), so grants are never coarser than necessary (Art. 7); `timestamp` — required for the grant/revoke history itself. This relationship metadata (who has access to what) is retained only as long as the underlying resource exists; it is deleted when the resource is deleted, not kept as an independent record.
- **Art. 10 (modularity):** Permissions is the single source of truth for access-control decisions — other capabilities must call `CheckPermission` rather than reimplementing an ad hoc check, which is itself checked mechanically over time as more capabilities land (extending `check-modularity.sh`'s conventions).

## 5. Experience budget

Zero-config default: new resources are private to their owner until explicitly shared — no permission dialog required for the common case. "Transparent when curious": a per-resource "who has access" view, one tap away, not buried in settings. "Powerful when needed": a rule-based policy editor for power users who want conditional/automated sharing rules (Art. 11), kept out of the default flow entirely.

## 6. Threat model

In scope — Permissions is a security-sensitive surface by definition.

- **Confused deputy risk:** a capability that calls `CheckPermission` on behalf of a user must pass the true acting subject, never a capability's own service identity, or checks become meaningless.
- **Privilege escalation via grant chains:** if a subject can grant permissions they don't themselves fully hold (e.g. re-sharing), the model must make that explicit and boundable, not accidental.
- **Default-policy gaps:** any resource type that comes online without registering a `DefinePolicy` default must fail closed (deny by default), never fail open.

## 7. Open questions / risks

- **Mutual dependency shape with Audit and Identity — resolved.** Per `docs/DECISION_LOG.md`, 2026-07-06 ("Foundation contracts composition: opaque references, no live cycle"), Permissions, Audit, and Identity reference each other only via opaque contract-level identifiers, never a concrete struct crossing a package boundary, and Audit's permission-gating on `Query`/`Explain` is resolved lazily at call time rather than requiring a live circular initialization. See Identity charter §7 for the full statement of this resolution.
- Rule-language design for user-authored policies (Art. 6, 11) is deferred to the capability engineer's implementation, informed by Experience Guardian's cognitive-budget constraint once this charter is frozen.

## 8. Guardian gate results

| Guardian | Verdict (✅ pass / 🚫 blocked / N/A) | Notes | Date |
|---|---|---|---|
| Constitution Warden | ✅ pass (after amendment) | Initially blocked on the same unresolved contract cycle as Identity/Audit, and a missing Art. 8 obligation for grant records; both resolved. | 2026-07-06 |
| Experience Guardian | ✅ pass | Owner-private-by-default is a genuine excellent default; rule-based policy editor correctly quarantined from the default flow, flagged for its own future Experience Guardian pass when designed. | 2026-07-06 |
| Security Steward | ✅ pass | No blocking findings — fail-closed default-policy handling and grant/revoke attributability are concrete and sound. | 2026-07-06 |

## 9. Decision log references

See `docs/DECISION_LOG.md`, 2026-07-06 entries for Phase 1 chartering.
