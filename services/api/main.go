package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/ascend/services/api/internal/audit"
	"github.com/ascend/services/api/internal/fileobjects"
	"github.com/ascend/services/api/internal/identity"
	"github.com/ascend/services/api/internal/permissions"
	"github.com/ascend/services/api/internal/platform"
	"github.com/ascend/services/api/internal/sessionauth"
	"github.com/ascend/services/api/internal/storage"
)

// maxRequestBodyBytes bounds every request body this server accepts.
// Added 2026-08-16 per Security Steward's merge-gate finding on the first
// network wiring pass: an unbounded body reader on a now-network-reachable
// service is a real resource-exhaustion surface, not a hypothetical one —
// live-tested with a 5MB body before this fix, which was accepted with no
// rejection until business-logic field validation happened to catch it.
// 1MiB is generous for anything this API currently accepts (a display
// name, a 32-byte public key, small JSON bodies) and can be raised later
// if a real capability needs more, deliberately, not by omission.
const maxRequestBodyBytes = 1 << 20 // 1 MiB

func limitRequestBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
		next.ServeHTTP(w, r)
	})
}

// main wires the HTTP server. Capability handlers are mounted here once
// chartered and frozen — see docs/CAPABILITY_REGISTRY.md. No capability
// logic lives in this file; cross-capability composition (dependency
// injection, HTTP middleware seams) lives in wiring.go alongside it.
//
// Scope of this wiring pass (docs/DECISION_LOG.md, 2026-08-16, "Identity
// wiring design", "Permissions and Audit wiring design", and "Storage and
// File Objects wiring design"): Identity, Session/Request Authentication,
// Permissions (five of seven routes — DefinePolicy and
// ListGrantsForResource are excluded, see the decision log), Audit (all
// four routes), Storage (all seven routes), and File Objects (all ten
// routes) are all mounted on the network. This is the first time the
// three-way Identity/Permissions/Audit opaque-reference/lazy-resolution
// design is exercised for real — see lateBoundPermissionChecker in
// wiring.go for the concrete construction-order mechanics. Storage and File
// Objects are the last two backend capabilities to come online this pass;
// every backend capability chartered so far is now network-reachable.
//
// Real database infrastructure landed 2026-08-16 (docs/DECISION_LOG.md,
// "Database setup: shared platform foundation + Audit on real Postgres"):
// Audit was the first capability backed by real Postgres. Extended
// 2026-08-17 across three batches ("Migrating remaining capabilities onto
// Postgres: batch plan") — Batch A (Identity, Permissions), Batch B
// (Storage metadata, File Objects), and Batch C (Session/Request
// Authentication, split across Postgres for sessions and Redis for
// challenge nonces — the only capability using Redis so far). Every
// backend capability's durable data now survives a restart. Storage's blob
// *bytes* still live on the local filesystem (unchanged Backend/
// FilesystemBackend) — only its metadata moved to Postgres. The shared
// internal/platform package's S3-compatible client is still constructed
// and health-checked at startup but consumed by nothing yet, reserved for
// a future pass wiring Storage's blob bytes onto it.
//
// newRouter builds the composition root and full HTTP router, given an
// already-constructed Platform (docs/DECISION_LOG.md, 2026-08-16, "Database
// setup: shared platform foundation + Audit on real Postgres"). plat is
// constructed once by main() (or once per test binary by main_test.go's
// TestMain) — never inside newRouter itself — specifically so migrations
// don't re-run and a fresh connection pool isn't opened on every call; a
// real integration test suite calls newRouter repeatedly (once per
// httptest.Server) and must reuse one Platform, not accumulate one per
// test. Split out from main() so an integration test can exercise the
// real, fully-wired server (via httptest) without a separate process — see
// main_test.go.
func newRouter(plat *platform.Platform) http.Handler {
	// --- Composition root: construct real capability instances, wired
	// together via each capability's own DI interfaces, not fakes. ---

	// Audit and Permissions depend on each other (Audit needs Permissions
	// to gate cross-subject Query/Explain; Permissions needs Audit to log
	// its own grants/revokes) — broken via a late-bound pointer, patched
	// immediately below once both exist. See lateBoundPermissionChecker's
	// own doc comment in wiring.go for the full rationale.
	checker := &lateBoundPermissionChecker{}

	// Audit is now backed by real Postgres, not InMemoryStore — the first
	// capability in this build to survive a server restart. No in-memory
	// fallback: a misconfigured/unreachable Postgres fails server startup
	// entirely (see main(), which log.Fatalf's on platform.New's error)
	// rather than silently discarding audit history, matching this
	// codebase's existing fail-fast-on-construction-error precedent
	// (Storage/File Objects below do the same for their own errors).
	auditStore := audit.NewPostgresStore(plat.DB)
	auditSvc := audit.NewService(auditStore, checker)

	// Permissions and Identity are now also backed by real Postgres
	// (docs/DECISION_LOG.md, 2026-08-17, "Migrating remaining capabilities
	// onto Postgres: batch plan" — Batch A). Permissions' Store became a
	// real interface in this same pass (previously a concrete *Store);
	// NewPostgresStore satisfies it exactly like NewInMemoryStore always
	// did, so this is the only line that changed in Permissions' own
	// wiring here.
	permissionsStore := permissions.NewPostgresStore(plat.DB)
	permsSvc := permissions.NewService(permissionsStore, permissionsAuditEmitterAdapter{audit: auditSvc})

	checker.svc = permsSvc // patch the late-bound reference now that both exist

	identityStore := identity.NewPostgresStore(plat.DB)
	identitySvc := identity.NewService(identityStore, auditSvc) // *audit.Service satisfies identity.AuditEmitter directly (type-alias ResourceRef)

	// Session/Request Authentication is Batch C (docs/DECISION_LOG.md,
	// 2026-08-17, "Batch C (Session/Request Authentication) design"), the
	// last capability in the database-migration series and the only one
	// split across two backends: challenge nonces (pure ephemeral, no
	// durability/export need) go to Redis; sessions (ExportSessions must
	// show expired-but-not-yet-revoked sessions) go to Postgres. Every
	// backend capability's durable data now survives a restart.
	sessionAuthSvc := sessionauth.NewService(
		sessionauth.NewRedisNonceStore(plat.Redis),
		sessionauth.NewPostgresSessionStore(plat.DB),
		deviceResolverAdapter{identity: identitySvc},
		auditEmitterAdapter{audit: auditSvc},
	)

	// Storage and File Objects (docs/DECISION_LOG.md, 2026-08-16, "Storage
	// and File Objects wiring design"): both constructors call DefinePolicy
	// on permsSvc via the adapters below (registering "blob" and
	// "file_object"'s default policies respectively) as part of their own
	// NewService — this is what actually closes the CheckPermission
	// fail-closed-for-unregistered-resource-type gap tracked in
	// docs/CAPABILITY_REGISTRY.md since the Permissions/Audit wiring pass;
	// no code change was needed there, only reaching this construction
	// point for the first time. File Objects is constructed after Storage
	// and depends on it directly (fileobjectsStorageClientAdapter) — no
	// circular dependency here, unlike Audit/Permissions.
	//
	// Both metadata stores are now real Postgres too (docs/DECISION_LOG.md,
	// 2026-08-17, "Migrating remaining capabilities onto Postgres: batch
	// plan" — Batch B). Storage's blob *bytes* still live on the local
	// filesystem (NewFilesystemService's own two local-disk policies,
	// unchanged) — only blob metadata (owner, policy_id, location,
	// tombstone fields) and the outer wrapping keys moved to Postgres.
	storageSvc, err := storage.NewFilesystemService(
		storage.NewPostgresStore(plat.DB),
		storagePermissionCheckerAdapter{perms: permsSvc},
		storageAuditEmitterAdapter{audit: auditSvc},
	)
	if err != nil {
		log.Fatalf("constructing storage service: %v", err)
	}

	fileobjectsSvc, err := fileobjects.NewService(
		fileobjects.NewPostgresStore(plat.DB),
		fileobjectsStorageClientAdapter{storage: storageSvc},
		fileobjectsPermissionsClientAdapter{perms: permsSvc},
		fileobjectsAuditEmitterAdapter{audit: auditSvc},
	)
	if err != nil {
		log.Fatalf("constructing file objects service: %v", err)
	}

	// --- HTTP layer ---
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(limitRequestBody)

	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	sessionauth.Mount(r, sessionAuthSvc)

	r.Mount("/v1/identity", identity.Mount(
		identitySvc,
		requireCallerMatchesIdentity(sessionAuthSvc, "identityRef"),
	))

	// Audit and Permissions both derive the acting identity entirely from
	// the verifiedCallerHeader value (no path parameter to match, unlike
	// Identity) — requireVerifiedCaller is scoped via r.Group so it applies
	// only to what each capability mounts here, never leaking onto
	// /healthz, /v1/identity/*, or /v1/sessionauth/*.
	r.Group(func(r chi.Router) {
		r.Use(requireVerifiedCaller(sessionAuthSvc))
		audit.Mount(r, auditSvc)
	})
	r.Group(func(r chi.Router) {
		permissions.Mount(r, permsSvc, requireVerifiedCaller(sessionAuthSvc))
	})

	// Storage and File Objects each read the verified caller directly from
	// verifiedCallerHeader inside their own handlers (mirroring Audit's
	// Mount shape, not Permissions' — see storage/http.go's and
	// fileobjects/http.go's own Mount doc comments), so — like Audit —
	// requireVerifiedCaller is applied externally via r.Group rather than
	// threaded through Mount's parameters.
	r.Group(func(r chi.Router) {
		r.Use(requireVerifiedCaller(sessionAuthSvc))
		storage.Mount(r, storageSvc)
	})
	r.Group(func(r chi.Router) {
		r.Use(requireVerifiedCaller(sessionAuthSvc))
		fileobjects.Mount(r, fileobjectsSvc)
	})

	return r
}

func main() {
	ctx := context.Background()

	// Platform (Postgres pool + migrations, Redis client, S3-compatible
	// client) is constructed once, here, before any capability — every
	// error here is fatal at startup, not a silent degrade (see
	// platform.New's own doc comment). See docs/DECISION_LOG.md,
	// 2026-08-16, "Database setup: shared platform foundation + Audit on
	// real Postgres".
	cfg, err := platform.ConfigFromEnv()
	if err != nil {
		log.Fatalf("loading platform configuration: %v", err)
	}
	plat, err := platform.New(ctx, cfg)
	if err != nil {
		log.Fatalf("constructing platform (postgres/redis/s3): %v", err)
	}
	defer plat.Close()

	addr := ":8080"
	// Explicit timeouts, not the http.ListenAndServe default of "none" —
	// added 2026-08-16 alongside the body-size cap above, same finding:
	// an unbounded read/write/idle window on a network-reachable server
	// is a real Slowloris-class exposure once this stopped being an
	// in-process-only test surface. Values are conservative defaults for
	// a JSON API with no long-lived connections (e.g. no streaming/SSE
	// endpoints exist yet); revisit deliberately if one is added.
	srv := &http.Server{
		Addr:              addr,
		Handler:           newRouter(plat),
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Printf("services/api listening on %s", addr)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
