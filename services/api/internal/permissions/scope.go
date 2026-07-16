package permissions

import "strings"

// scopeRank gives a small set of well-known scope strings a total order,
// so "a grantor can only grant a scope they themselves hold an
// equal-or-greater grant for" (charter §6 threat model) is mechanically
// checkable rather than a matter of string equality alone. See
// docs/DECISION_LOG.md for why this specific set/ordering was chosen.
//
// An empty scope is treated as "full" (unbounded within the action) — the
// natural default when a caller doesn't narrow a grant.
var scopeRank = map[string]int{
	"read":  1,
	"write": 2,
	"full":  3,
	"owner": 4,
}

func normalizeScope(scope string) string {
	if scope == "" {
		return "full"
	}
	return strings.ToLower(scope)
}

// scopeAtLeast reports whether `held` is an equal-or-greater scope than
// `requested`. Known scopes (see scopeRank) compare by rank. A scope
// string outside that known set is only ever "equal-or-greater" than
// itself — an unrecognized custom scope never implicitly outranks or is
// outranked by anything, it must match exactly. This keeps the escalation
// rule conservative by construction: an unknown scope can never be used to
// bluff past a rank check.
func scopeAtLeast(held, requested string) bool {
	h, hKnown := scopeRank[normalizeScope(held)]
	r, rKnown := scopeRank[normalizeScope(requested)]
	if hKnown && rKnown {
		return h >= r
	}
	return normalizeScope(held) == normalizeScope(requested)
}
