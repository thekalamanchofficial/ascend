package sessionauth

import (
	"fmt"
	"strconv"
	"time"
)

// DefaultSessionLifetime/DefaultChallengeNonceLifetime are this
// implementation's exact numeric answers to charter §7's open questions
// ("exact numeric value of expires_at's lifetime... left to the capability
// engineer"). 30 minutes for a session: short enough that a leaked token's
// blast radius (charter §6, "the worst case for a leaked token is bounded
// by expires_at at the moment of leak") is genuinely small — low enough
// that "minutes-to-low-hours" from the brief is satisfied on the minutes
// side — while long enough that, combined with the charter §5/§6-mandated
// automatic background renewal (fresh GetSessionChallenge + IssueSession
// well before expiry), a real client re-signs roughly every 20-25 minutes
// rather than needing sub-minute renewal traffic. 2 minutes for a challenge
// nonce: it only needs to survive one round trip (client requests a
// challenge, signs it, and immediately calls IssueSession) — 2 minutes is
// generous slack for real-world latency/clock skew while still being
// "seconds/low minutes" per charter §4's data-manifest guidance, and short
// enough that an intercepted-but-unused nonce is worthless to a replay
// attempt well before any human would notice. Both are logged as
// non-trivial decisions in docs/DECISION_LOG.md.
const (
	DefaultSessionLifetime        = 30 * time.Minute
	DefaultChallengeNonceLifetime = 2 * time.Minute
)

// Service implements the seven SessionAuthService RPCs (sessionauth.proto)
// against two in-memory stores and two injected seams (DeviceResolver,
// AuditEmitter) — see NewService and types.go.
type Service struct {
	nonces   *nonceStore
	sessions *sessionStore
	failures *failureTracker

	devices DeviceResolver
	audit   AuditEmitter

	sessionLifetime time.Duration
	nonceLifetime   time.Duration

	// now is a seam for deterministic expiry testing; production callers
	// never set it (NewService defaults it to time.Now). Kept unexported —
	// tests in this package construct a Service via NewService and then
	// override this field directly (white-box), following no special
	// convention beyond Go's own package-private visibility.
	now func() time.Time
}

// NewService wires a Service. `devices` resolves current device public
// keys (Identity's data, via DI — see types.go's DeviceResolver); a nil
// devices seam defaults to a resolver that always reports "not found",
// which fails IssueSession closed rather than open if a caller forgets to
// wire one. `emitter` is the Art. 5 audit seam; a nil emitter defaults to
// NoopAuditEmitter, which fails loudly (returns an error) rather than
// silently dropping audit events — mirroring Identity's/Permissions'
// identical precedent.
func NewService(devices DeviceResolver, emitter AuditEmitter) *Service {
	if devices == nil {
		devices = alwaysNotFoundDeviceResolver{}
	}
	if emitter == nil {
		emitter = NoopAuditEmitter{}
	}
	return &Service{
		nonces:          newNonceStore(),
		sessions:        newSessionStore(),
		failures:        newFailureTracker(),
		devices:         devices,
		audit:           emitter,
		sessionLifetime: DefaultSessionLifetime,
		nonceLifetime:   DefaultChallengeNonceLifetime,
		now:             time.Now,
	}
}

type alwaysNotFoundDeviceResolver struct{}

func (alwaysNotFoundDeviceResolver) ResolveDevicePublicKey(_, _ string) ([]byte, bool, error) {
	return nil, false, nil
}

// GetSessionChallenge issues a random, single-use, short-lived nonce.
// Deliberately not marked ascend:mutates / not audited: it exists purely as
// a freshness input for IssueSession (charter §3), carries no security
// decision of its own (issuing a challenge authorizes nothing), and the
// charter's own audit-obligations section (§4) does not name it — only
// IssueSession, RevokeSession, RevokeAllSessions, and repeated
// ValidateSession failures are audited, by explicit charter judgment.
func (s *Service) GetSessionChallenge(req GetSessionChallengeRequest) (GetSessionChallengeResponse, error) {
	if req.IdentityRef == "" {
		return GetSessionChallengeResponse{}, fmt.Errorf("%w: identity_ref is required", ErrInvalidArgument)
	}
	if req.DeviceID == "" {
		return GetSessionChallengeResponse{}, fmt.Errorf("%w: device_id is required", ErrInvalidArgument)
	}

	now := s.now()
	nonce := generateChallengeNonce()
	expiresAt := now.Add(s.nonceLifetime).Unix()

	s.nonces.put(nonce, nonceRecord{
		IdentityRef:   req.IdentityRef,
		DeviceID:      req.DeviceID,
		ExpiresAtUnix: expiresAt,
	})

	return GetSessionChallengeResponse{
		ChallengeNonce:         nonce,
		ChallengeExpiresAtUnix: expiresAt,
	}, nil
}

// IssueSession verifies a fresh Ed25519 device signature over the
// canonical, domain-separated message (sign.go) and, on success, issues a
// brand-new server-side session. Every step below is required, in order,
// per charter §3 — see sign.go and store.go for why each is structured the
// way it is.
//
// ascend:mutates
func (s *Service) IssueSession(req IssueSessionRequest) (IssueSessionResponse, error) {
	if req.IdentityRef == "" {
		return IssueSessionResponse{}, fmt.Errorf("%w: identity_ref is required", ErrInvalidArgument)
	}
	if req.DeviceID == "" {
		return IssueSessionResponse{}, fmt.Errorf("%w: device_id is required", ErrInvalidArgument)
	}
	if req.ChallengeNonce == "" {
		return IssueSessionResponse{}, fmt.Errorf("%w: challenge_nonce is required", ErrInvalidArgument)
	}
	if len(req.Proof) == 0 {
		return IssueSessionResponse{}, fmt.Errorf("%w: proof is required", ErrInvalidArgument)
	}

	now := s.now()

	// Step 1 (charter §3): nonce must exist, be unexpired, not already
	// consumed. This is a fast-fail check, NOT the atomic anti-replay gate
	// (see consumeIfValid at step 4) — a nonce that passes this check can
	// still lose the race to a concurrent replay at step 4.
	if !s.nonces.peek(req.ChallengeNonce, req.IdentityRef, req.DeviceID, now) {
		s.auditIssueRejected(req.IdentityRef, req.DeviceID, "invalid_or_expired_or_consumed_nonce")
		return IssueSessionResponse{}, ErrInvalidNonce
	}

	// Step 2 (charter §3, closing the same class of gap as Identity's
	// BindDevice replay fix): resolve the device's CURRENT public key via
	// the injected DeviceResolver. A revoked/unbound device must resolve as
	// not-found here, regardless of whether it once held a valid key.
	publicKey, found, err := s.devices.ResolveDevicePublicKey(req.IdentityRef, req.DeviceID)
	if err != nil {
		return IssueSessionResponse{}, fmt.Errorf("%w: %v", ErrDeviceResolutionFailed, err)
	}
	if !found {
		s.auditIssueRejected(req.IdentityRef, req.DeviceID, "device_not_currently_bound")
		return IssueSessionResponse{}, ErrDeviceNotBound
	}

	// Step 3 (charter §3): verify proof via unmodified crypto/ed25519.Verify
	// against the canonical, domain-separated message.
	message := buildIssueSessionMessage(req.IdentityRef, req.DeviceID, req.ChallengeNonce)
	if !verifyProof(publicKey, message, req.Proof) {
		s.auditIssueRejected(req.IdentityRef, req.DeviceID, "invalid_signature")
		return IssueSessionResponse{}, ErrInvalidSignature
	}

	// Step 4 (charter §3): consume the nonce atomically, AFTER successful
	// verification. This is the actual anti-replay gate — see store.go's
	// consumeIfValid doc comment for why this ordering (verify first, then
	// atomically consume) is what makes concurrent replay of a captured
	// request impossible, not merely inconvenient.
	if !s.nonces.consumeIfValid(req.ChallengeNonce, req.IdentityRef, req.DeviceID, now) {
		s.auditIssueRejected(req.IdentityRef, req.DeviceID, "nonce_already_consumed_concurrently")
		return IssueSessionResponse{}, ErrInvalidNonce
	}

	// Step 5 (charter §3): create the new session record.
	token := generateSessionToken()
	expiresAt := now.Add(s.sessionLifetime).Unix()
	sess := Session{
		SessionToken:   token,
		IdentityRef:    req.IdentityRef,
		DeviceID:       req.DeviceID,
		IssuedAtUnix:   now.Unix(),
		ExpiresAtUnix:  expiresAt,
		LastUsedAtUnix: now.Unix(),
	}
	s.sessions.put(sess)

	if _, err := s.audit.Emit(req.IdentityRef, "sessionauth.session_issued",
		ResourceRef{ResourceType: "identity_device", ResourceID: req.DeviceID},
		"sessionauth.issue_session.signature_verified",
		map[string]string{
			"identity_ref": req.IdentityRef,
			"device_id":    req.DeviceID,
			// session_token is deliberately NEVER included in audit
			// metadata (DATA_MANIFEST.md / Art. 8) — it is a live bearer
			// credential, not an event detail.
		}); err != nil {
		return IssueSessionResponse{}, fmt.Errorf("session issued but audit emit failed: %w", err)
	}

	return IssueSessionResponse{SessionToken: token, ExpiresAtUnix: expiresAt}, nil
}

// auditIssueRejected is a small helper so every IssueSession failure path
// above emits the same event shape (charter §4: "IssueSession — success and
// failure, including nonce-reuse/expiry rejections and signature-
// verification failures — audited"). Errors from Emit on a rejection path
// are deliberately swallowed via `_, _ =` here, matching Identity's own
// established precedent for reject-path audit calls (identity/service.go's
// BindDevice/RevokeDevice) — a rejection is already being reported to the
// caller via the returned error; failing to also log it to the audit trail
// must not additionally fail the (already-failing) RPC call itself, but the
// error is not silently ignored in the sense of going unnoticed: the
// primary error return already surfaces the failure to the caller.
func (s *Service) auditIssueRejected(identityRef, deviceID, reason string) {
	_, _ = s.audit.Emit(identityRef, "sessionauth.issue_session_rejected",
		ResourceRef{ResourceType: "identity_device", ResourceID: deviceID},
		"sessionauth.issue_session."+reason,
		map[string]string{
			"identity_ref": identityRef,
			"device_id":    deviceID,
			"reason":       reason,
		})
}

// ValidateSession is a real, server-side lookup every time — never a
// self-contained/stateless token whose validity can't be revoked (charter
// §3/§6/Art. 7). Returns valid: false for unknown, expired, or revoked
// tokens. On success it updates last_used_at but deliberately does NOT
// audit routine successes (charter §4, a deliberate judgment, not an
// oversight) — every other capability validates a session on effectively
// every request, so logging each one would flood the audit trail. Repeated
// failures for the same token within a short window ARE audited, as an
// anomaly signal (charter §4, anomaly.go).
func (s *Service) ValidateSession(req ValidateSessionRequest) (ValidateSessionResponse, error) {
	now := s.now()

	if req.SessionToken != "" {
		if sess, ok := s.sessions.get(req.SessionToken); ok && now.Unix() <= sess.ExpiresAtUnix {
			s.sessions.touchLastUsed(req.SessionToken, now.Unix())
			return ValidateSessionResponse{
				IdentityRef: sess.IdentityRef,
				DeviceID:    sess.DeviceID,
				Valid:       true,
			}, nil
		}
	}

	s.recordValidationFailure(req.SessionToken, now)
	return ValidateSessionResponse{Valid: false}, nil
}

func (s *Service) recordValidationFailure(token string, now time.Time) {
	if token == "" {
		return
	}
	fingerprint := tokenFingerprint(token)
	if s.failures.recordFailure(fingerprint, now) {
		_, _ = s.audit.Emit("", "sessionauth.validate_session_anomaly",
			ResourceRef{ResourceType: "session_token_fingerprint", ResourceID: fingerprint},
			"sessionauth.validate_session.repeated_failures",
			map[string]string{
				"threshold_failures": strconv.Itoa(validateFailureThreshold),
				"window_seconds":     strconv.Itoa(int(validateFailureWindow.Seconds())),
			})
	}
}

// RevokeSession signs a single session out. The token itself is sufficient
// authorization to revoke itself (charter §3) — no additional check is
// performed beyond "this token currently identifies a real session."
//
// ascend:mutates
func (s *Service) RevokeSession(req RevokeSessionRequest) (RevokeSessionResponse, error) {
	if req.SessionToken == "" {
		return RevokeSessionResponse{}, fmt.Errorf("%w: session_token is required", ErrInvalidArgument)
	}

	sess, ok := s.sessions.get(req.SessionToken)
	if !ok {
		_, _ = s.audit.Emit("", "sessionauth.revoke_session_rejected",
			ResourceRef{ResourceType: "session_token_fingerprint", ResourceID: tokenFingerprint(req.SessionToken)},
			"sessionauth.revoke_session.unknown_token",
			map[string]string{"reason": "unknown_or_already_revoked_session_token"})
		return RevokeSessionResponse{}, ErrSessionNotFound
	}

	s.sessions.delete(req.SessionToken)

	if _, err := s.audit.Emit(sess.IdentityRef, "sessionauth.session_revoked",
		ResourceRef{ResourceType: "identity_device", ResourceID: sess.DeviceID},
		"sessionauth.revoke_session",
		map[string]string{
			"identity_ref": sess.IdentityRef,
			"device_id":    sess.DeviceID,
		}); err != nil {
		return RevokeSessionResponse{}, fmt.Errorf("session revoked but audit emit failed: %w", err)
	}

	return RevokeSessionResponse{}, nil
}

// resolveCaller resolves caller_session_token to the (still-valid, not
// expired) session it identifies — the shared authorization step charter
// §3 requires RevokeAllSessions, ListActiveSessions, and ExportSessions to
// all perform BEFORE doing anything else, so every one of those three RPCs
// operates only on the identity the caller's own presented token already
// resolves to, never a separately-supplied identity_ref (the frozen
// contract does not even have such a field on any of the three request
// messages — this is enforced structurally by the wire contract, and this
// function is the runtime half of that guarantee).
func (s *Service) resolveCaller(callerSessionToken string, now time.Time) (Session, bool) {
	if callerSessionToken == "" {
		return Session{}, false
	}
	sess, ok := s.sessions.get(callerSessionToken)
	if !ok {
		return Session{}, false
	}
	if now.Unix() > sess.ExpiresAtUnix {
		return Session{}, false
	}
	return sess, true
}

// RevokeAllSessions signs the caller's identity out everywhere. Resolves
// caller_session_token via resolveCaller first (charter §3) and operates
// only on that resolved identity_ref's sessions.
//
// ascend:mutates
func (s *Service) RevokeAllSessions(req RevokeAllSessionsRequest) (RevokeAllSessionsResponse, error) {
	now := s.now()
	sess, ok := s.resolveCaller(req.CallerSessionToken, now)
	if !ok {
		_, _ = s.audit.Emit("", "sessionauth.revoke_all_sessions_rejected",
			ResourceRef{ResourceType: "session_token_fingerprint", ResourceID: tokenFingerprint(req.CallerSessionToken)},
			"sessionauth.revoke_all_sessions.invalid_caller_session",
			map[string]string{"reason": "caller_session_token_invalid_expired_or_revoked"})
		return RevokeAllSessionsResponse{}, ErrSessionInvalid
	}

	count := s.sessions.deleteAllForIdentity(sess.IdentityRef)

	if _, err := s.audit.Emit(sess.IdentityRef, "sessionauth.all_sessions_revoked",
		ResourceRef{ResourceType: "identity", ResourceID: sess.IdentityRef},
		"sessionauth.revoke_all_sessions",
		map[string]string{
			"identity_ref":     sess.IdentityRef,
			"sessions_revoked": strconv.Itoa(count),
		}); err != nil {
		return RevokeAllSessionsResponse{}, fmt.Errorf("sessions revoked but audit emit failed: %w", err)
	}

	return RevokeAllSessionsResponse{SessionsRevoked: int32(count)}, nil
}

// ListActiveSessions returns the caller's own currently-active sessions
// (device_id/issued_at/expires_at/last_used_at, per SessionSummary — never
// session_token). Resolves caller_session_token first, same authorization
// shape as RevokeAllSessions/ExportSessions. Not marked ascend:mutates and
// does not call audit.Emit: charter §4's audit-obligations section does not
// name this RPC (only IssueSession, RevokeSession, RevokeAllSessions, and
// repeated ValidateSession failures are audited) — a deliberate charter
// scoping, not an oversight for this capability engineer to "fix".
func (s *Service) ListActiveSessions(req ListActiveSessionsRequest) (ListActiveSessionsResponse, error) {
	now := s.now()
	sess, ok := s.resolveCaller(req.CallerSessionToken, now)
	if !ok {
		return ListActiveSessionsResponse{}, ErrSessionInvalid
	}

	active := s.sessions.listActiveForIdentity(sess.IdentityRef, now.Unix())
	summaries := make([]SessionSummary, len(active))
	for i, a := range active {
		summaries[i] = SessionSummary{
			DeviceID:       a.DeviceID,
			IssuedAtUnix:   a.IssuedAtUnix,
			ExpiresAtUnix:  a.ExpiresAtUnix,
			LastUsedAtUnix: a.LastUsedAtUnix,
		}
	}
	return ListActiveSessionsResponse{Sessions: summaries}, nil
}

// ExportSessions exports identity_ref/device_id/issued_at/expires_at/
// last_used_at for every one of the caller's own sessions (charter §3), in
// a versioned, self-describing format (export.go) — session_token is
// structurally excluded (see export.go's exportedSession shape, which has
// no field for it at all). Resolves caller_session_token first, same
// authorization shape as RevokeAllSessions/ListActiveSessions. Not marked
// ascend:mutates and does not call audit.Emit — same charter §4 scoping
// reasoning as ListActiveSessions above (this RPC is not named in the
// audit-obligations section).
func (s *Service) ExportSessions(req ExportSessionsRequest) (ExportSessionsResponse, error) {
	now := s.now()
	sess, ok := s.resolveCaller(req.CallerSessionToken, now)
	if !ok {
		return ExportSessionsResponse{}, ErrSessionInvalid
	}

	all := s.sessions.listAllForIdentity(sess.IdentityRef)
	blob, formatVersion, err := ExportSessionsBundle(sess.IdentityRef, all)
	if err != nil {
		return ExportSessionsResponse{}, err
	}

	return ExportSessionsResponse{ExportBlob: blob, FormatVersion: formatVersion}, nil
}
