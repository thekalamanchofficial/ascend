// Package platform holds shared, capability-agnostic infrastructure: the
// Postgres connection pool, Redis client, S3-compatible object-storage
// client, and migration runner every capability's own durable-storage
// implementation is built on top of. It is deliberately the second package
// (alongside internal/audit) exempted from Art. 10's mechanical
// cross-capability-import check (scripts/constitution/check-modularity.sh's
// shared_exempt list) — that exemption already anticipated exactly this
// package's existence and name, see docs/DECISION_LOG.md, "Database setup:
// shared platform foundation + Audit on real Postgres".
//
// This package knows nothing about any capability's schema, queries, or
// domain types — it hands back a generic *pgxpool.Pool/*redis.Client/
// *s3.Client and nothing more. Each capability's own Postgres-backed store
// (e.g. internal/audit/postgres_store.go) owns its own SQL entirely.
package platform

import (
	"errors"
	"fmt"
	"os"
)

// Config is every connection setting this service's composition root needs,
// read once from the environment at startup. No field here defaults a
// secret or a connection target silently — an empty required value fails
// construction rather than quietly falling back to something that "happens
// to work" locally and masks a missing production config. Local-dev-shaped
// defaults belong in .env.example/docker-compose.yml, not baked in here.
type Config struct {
	// DatabaseURL is the connection string the running application uses
	// day to day — the least-privilege app role (ascend_app), never the
	// migration-time admin role. Required.
	DatabaseURL string
	// MigrationsDatabaseURL is a SEPARATE, more privileged connection
	// string used only at startup to run schema migrations (CREATE TABLE,
	// REVOKE, CREATE ROLE) — kept distinct from DatabaseURL specifically so
	// the day-to-day running application never holds schema-owning
	// privileges (docs/DECISION_LOG.md, "Database setup..."). Required.
	MigrationsDatabaseURL string
	// AppDBPassword is the password platform.go's role-provisioning step
	// sets for the ascend_app role via a parameterized ALTER ROLE
	// statement (never embedded in a committed .sql migration file).
	// Required.
	AppDBPassword string

	// RedisURL is the connection string for the Redis client. Required —
	// even though nothing consumes this client yet this pass (see
	// wiring.go), the composition root still constructs and health-checks
	// it at startup so the foundation is proven end to end, not just
	// partially wired.
	RedisURL string

	// S3Endpoint/S3Bucket/S3AccessKey/S3SecretKey/S3Region/S3UsePathStyle
	// configure the S3-compatible object-storage client — works unchanged
	// against MinIO locally (S3UsePathStyle=true) and DigitalOcean
	// Spaces/real S3 later (only these values change). Required, except
	// S3Region/S3UsePathStyle which have sane, documented defaults below.
	S3Endpoint     string
	S3Bucket       string
	S3AccessKey    string
	S3SecretKey    string
	S3Region       string
	S3UsePathStyle bool
}

// ConfigFromEnv reads Config from the process environment. Returns an error
// naming every missing required variable at once (not just the first one
// found) so a misconfigured environment is diagnosable in a single pass,
// not a frustrating one-at-a-time discovery loop.
func ConfigFromEnv() (Config, error) {
	cfg := Config{
		DatabaseURL:           os.Getenv("DATABASE_URL"),
		MigrationsDatabaseURL: os.Getenv("MIGRATIONS_DATABASE_URL"),
		AppDBPassword:         os.Getenv("ASCEND_APP_DB_PASSWORD"),
		RedisURL:              os.Getenv("REDIS_URL"),
		S3Endpoint:            os.Getenv("S3_ENDPOINT"),
		S3Bucket:              os.Getenv("S3_BUCKET"),
		S3AccessKey:           os.Getenv("S3_ACCESS_KEY"),
		S3SecretKey:           os.Getenv("S3_SECRET_KEY"),
		S3Region:              os.Getenv("S3_REGION"),
		S3UsePathStyle:        true, // default true: required for MinIO; DigitalOcean Spaces also supports path-style, so this default is safe for both local and eventual prod.
	}
	if v := os.Getenv("S3_USE_PATH_STYLE"); v != "" {
		cfg.S3UsePathStyle = v != "false" && v != "0"
	}
	if cfg.S3Region == "" {
		cfg.S3Region = "us-east-1" // MinIO ignores region but the SDK requires a non-empty value.
	}

	// A slice, not a map, so the missing-variable list is reported in a
	// fixed, deterministic order every time — Go map iteration order is
	// randomized, which would make this error message (and any test
	// asserting against it) flaky for no reason.
	required := []struct{ name, value string }{
		{"DATABASE_URL", cfg.DatabaseURL},
		{"MIGRATIONS_DATABASE_URL", cfg.MigrationsDatabaseURL},
		{"ASCEND_APP_DB_PASSWORD", cfg.AppDBPassword},
		{"REDIS_URL", cfg.RedisURL},
		{"S3_ENDPOINT", cfg.S3Endpoint},
		{"S3_BUCKET", cfg.S3Bucket},
		{"S3_ACCESS_KEY", cfg.S3AccessKey},
		{"S3_SECRET_KEY", cfg.S3SecretKey},
	}
	var missing []string
	for _, r := range required {
		if r.value == "" {
			missing = append(missing, r.name)
		}
	}
	if len(missing) > 0 {
		return Config{}, fmt.Errorf("%w: %v (see .env.example)", ErrConfigMissing, missing)
	}
	return cfg, nil
}

// ErrConfigMissing is returned (wrapped, with the specific missing variable
// names) when required configuration is absent — a sentinel so a caller can
// errors.Is against this specific failure class rather than parsing
// ConfigFromEnv's message text.
var ErrConfigMissing = errors.New("platform: missing required environment variable(s)")
