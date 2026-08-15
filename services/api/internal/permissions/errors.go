package permissions

import "errors"

// ErrMissingCaller indicates this HTTP surface received no verified caller
// identity at all (the X-Ascend-Actor header was empty/absent) — meaning
// the composition-root session-auth middleware never ran, or the request
// was never authenticated. Distinguished (401) from ErrCallerMismatch
// (403), matching services/api/internal/audit/http.go's existing
// missing-vs-mismatched-caller convention. See docs/DECISION_LOG.md.
var ErrMissingCaller = errors.New("missing caller identity")

// ErrCallerMismatch indicates a verified network caller (from
// X-Ascend-Actor) named someone else — as grantor, subject, or
// identity_ref — in a request that requires the caller to act only as
// themselves. This is the HTTP-layer guard against the privilege-escalation
// path where any caller could grant/revoke/check/export permissions by
// simply naming an arbitrary identity in the request body or query string;
// it is additive to, not a replacement for, Service's own
// authorizeGrant/authorizeRevoke escalation-rule checks. See
// docs/DECISION_LOG.md.
var ErrCallerMismatch = errors.New("caller does not match the identity named in this request")
