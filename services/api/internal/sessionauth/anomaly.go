package sessionauth

import (
	"sync"
	"time"
)

// validateFailureThreshold/validateFailureWindow implement charter §4's
// "repeated ValidateSession failures for the same session_token within a
// short window also emit an event" obligation. Exact numbers are this
// capability engineer's implementation decision (charter §7 leaves them
// unspecified), logged in docs/DECISION_LOG.md: 5 failures within 1 minute
// for the same token is well above the handful of failures a legitimate
// client could produce from ordinary clock skew or a slightly-stale cached
// token re-presented once or twice after RevokeSession/expiry, but tight
// enough to catch a script repeatedly probing a stolen or guessed token.
const (
	validateFailureThreshold = 5
	validateFailureWindow    = 1 * time.Minute
)

// failureTracker is a goroutine-safe, process-local, in-memory tracker of
// recent ValidateSession failures per session_token, used only to decide
// when to emit the anomaly-signal audit event above — it is NOT part of
// this capability's persisted/exported data (DATA_MANIFEST.md deliberately
// does not list it: it is a transient counter, not a documented collected
// field, and it never appears in ExportSessions' output).
//
// Known, documented limitation of this first pass: entries are only ever
// removed when a window naturally rolls over and gets reset by a
// subsequent failure for the same token; a token that fails once and is
// never retried leaves a single small entry in memory indefinitely. This is
// an unbounded-growth concern under a sustained many-distinct-token probing
// attack, not a correctness bug — flagged here rather than worked around
// with a background sweep this first pass doesn't otherwise need.
type failureTracker struct {
	mu      sync.Mutex
	windows map[string]*failureWindow
}

type failureWindow struct {
	count       int
	windowStart time.Time
}

func newFailureTracker() *failureTracker {
	return &failureTracker{windows: make(map[string]*failureWindow)}
}

// recordFailure registers one more ValidateSession failure for
// tokenFingerprint (see token.go — callers pass the hashed fingerprint, not
// the raw token, so this type never sees or retains a live credential
// either). Returns true exactly when this failure just crossed
// validateFailureThreshold within validateFailureWindow, in which case the
// caller should emit the anomaly audit event; the window is reset
// immediately after crossing so a sustained failure stream emits the signal
// once per window rather than on every single subsequent failure (which
// would itself become the audit-trail noise problem charter §4 explicitly
// warns against for routine ValidateSession traffic).
func (f *failureTracker) recordFailure(fingerprint string, now time.Time) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	w, ok := f.windows[fingerprint]
	if !ok || now.Sub(w.windowStart) > validateFailureWindow {
		w = &failureWindow{windowStart: now}
		f.windows[fingerprint] = w
	}
	w.count++
	if w.count >= validateFailureThreshold {
		delete(f.windows, fingerprint)
		return true
	}
	return false
}
