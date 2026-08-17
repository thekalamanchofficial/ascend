package storage

import "fmt"

// Policy ID / display metadata for the two real, local-filesystem-backed
// policies this first pass advertises. See docs/DECISION_LOG.md, "Storage:
// two named local-filesystem policies" for why there are two (both
// genuinely working local-filesystem locations) rather than one: it is
// what makes MoveBlob's atomicity guarantee something this package can
// actually exercise and test against a real backend, rather than only a
// fake one, while still never advertising a policy this instance cannot
// currently honor (charter §5/§6) — no S3-compatible object store is
// deployed anywhere in this environment (this capability's spawn brief).
const (
	PolicyLocalDefault   = "local-default"
	PolicyLocalSecondary = "local-secondary"
)

// NewFilesystemService is the production-shaped constructor: two
// genuinely working local-filesystem policies, rooted under this
// package's own .data/ directory (gitignored — see backend.go's
// DefaultDataDir doc comment). This is the constructor the Chief
// Architect would call from services/api/main.go's future Storage wiring
// — NOT called from main.go by this capability-engineer, per the standing
// "no unauthenticated requesting_subject capability reaches the network
// perimeter yet" rule (see http.go's Mount doc comment).
//
// store is taken as the first parameter and passed straight through to
// NewService, unexamined — see NewService's doc comment for why (Store
// interface introduction, docs/DECISION_LOG.md "Storage: Store interface
// introduced, PostgresStore added"). Production wiring is expected to pass
// NewPostgresStore(pool); tests may pass NewInMemoryStore().
func NewFilesystemService(store Store, checker PermissionChecker, audit AuditEmitter) (*Service, error) {
	defaultBackend, err := NewFilesystemBackend(DefaultDataDir(PolicyLocalDefault))
	if err != nil {
		return nil, fmt.Errorf("storage: constructing default backend: %w", err)
	}
	secondaryBackend, err := NewFilesystemBackend(DefaultDataDir(PolicyLocalSecondary))
	if err != nil {
		return nil, fmt.Errorf("storage: constructing secondary backend: %w", err)
	}

	policies := []Policy{
		{
			ID:          PolicyLocalDefault,
			DisplayName: "This Device (Default)",
			Description: "The default local storage location on this device. Zero-config, fully encrypted end-to-end before Storage ever sees it.",
			Backend:     defaultBackend,
		},
		{
			ID:          PolicyLocalSecondary,
			DisplayName: "This Device (Secondary)",
			Description: "An additional local storage location on this device, for explicit relocation via MoveBlob.",
			Backend:     secondaryBackend,
		},
	}
	return NewService(store, policies, checker, audit)
}
