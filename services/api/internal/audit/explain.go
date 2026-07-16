package audit

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// renderExplanation turns e into a plain-language sentence.
//
// Template (documented per charter §3's instruction that, without other
// capabilities' real semantic knowledge wired in yet, Explain must
// synthesize honestly from the event's own fields rather than fabricate
// specifics it doesn't have):
//
//	On <RFC3339 timestamp>, <actor> performed '<action>' on <resource_type>
//	'<resource_id>'[, authorized by rule '<rule_reference>'][. Additional
//	context: <metadata k=v, ...>].
//
// The rule_reference clause is included only when non-empty; the resource
// clause is omitted when both resource fields are empty (some actions are
// not about a specific resource); the metadata clause is included only
// when metadata is non-empty, and lists keys in sorted order for
// determinism. No field is invented beyond what the event itself carries —
// a future pass with real semantic knowledge from Identity/Permissions
// (e.g. resolving `actor` to a display name, or `rule_reference` to a
// human policy description) can enrich this without changing the shape of
// this function's contract (it still takes just an AuditEvent).
func renderExplanation(e AuditEvent) string {
	ts := time.Unix(e.OccurredAtUnix, 0).UTC().Format(time.RFC3339)

	var b strings.Builder
	fmt.Fprintf(&b, "On %s, %s performed '%s'", ts, e.Actor, e.Action)

	if e.Resource.ResourceType != "" || e.Resource.ResourceID != "" {
		fmt.Fprintf(&b, " on %s '%s'", e.Resource.ResourceType, e.Resource.ResourceID)
	}

	if e.RuleReference != "" {
		fmt.Fprintf(&b, ", authorized by rule '%s'", e.RuleReference)
	}

	b.WriteString(".")

	if len(e.Metadata) > 0 {
		keys := make([]string, 0, len(e.Metadata))
		for k := range e.Metadata {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		pairs := make([]string, 0, len(keys))
		for _, k := range keys {
			pairs = append(pairs, fmt.Sprintf("%s=%s", k, e.Metadata[k]))
		}
		fmt.Fprintf(&b, " Additional context: %s.", strings.Join(pairs, ", "))
	}

	return b.String()
}
