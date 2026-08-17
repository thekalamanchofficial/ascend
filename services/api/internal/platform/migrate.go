package platform

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres" // registers the "postgres" migration driver
	_ "github.com/golang-migrate/migrate/v4/source/file"       // registers the "file" migration source
	"github.com/jackc/pgx/v5"
)

// defaultMigrationsDir returns the migrations/ directory colocated with
// this package's own source, computed via runtime.Caller (not the
// process's current working directory) so `go run .`/the compiled binary
// behaves identically regardless of where it's launched from — the same
// pattern services/api/internal/storage/backend.go's DefaultDataDir
// already establishes for the same reason.
func defaultMigrationsDir() string {
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(thisFile), "migrations")
}

// toFileURL converts a filesystem directory path into the "file:" URL
// golang-migrate's source/file driver expects. Verified directly against
// that driver's own parseURL (source/file/file.go, migrate v4.19.1): it
// computes the filesystem path as `u.Host + u.Path` UNLESS the URL is
// "opaque" (no "//" authority separator), in which case it uses `u.Opaque`
// verbatim instead — with no special-casing for a Windows drive letter
// either way. A triple-slash "file:///C:/Users/..." parses to
// Host="", Path="/C:/Users/...", giving the driver "/C:/Users/..." — a
// leading slash before the drive letter that os.DirFS rejects (confirmed
// live: this exact form produced "open .: The filename, directory name, or
// volume label syntax is incorrect."). The OPAQUE form "file:C:/Users/..."
// (no slashes after the colon) instead parses straight to
// Opaque="C:/Users/...", which the driver uses directly and os.DirFS
// accepts (Go's os.DirFS accepts forward-slash paths, drive letter
// included, since Go 1.20). Non-Windows absolute paths already start with
// "/", so the ordinary "file://" + path form works unchanged for them.
func toFileURL(dir string) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("resolving absolute path: %w", err)
	}
	abs = filepath.ToSlash(abs)
	if len(abs) >= 2 && abs[1] == ':' {
		return "file:" + abs, nil
	}
	return "file://" + abs, nil
}

// AppDBRole is the fixed, non-superuser Postgres role every capability's
// runtime connection (DatabaseURL) authenticates as — never the migration-
// time admin role (MigrationsDatabaseURL). Each migration that creates a
// capability's table is responsible for granting this role exactly the
// privileges that table needs (e.g. audit's 0001 migration grants
// SELECT/INSERT only, then REVOKEs UPDATE/DELETE — see
// internal/platform/migrations/0001_audit_events.up.sql). A fixed constant,
// not configurable, so every migration file can refer to it by the same
// literal name with no ambiguity.
const AppDBRole = "ascend_app"

// RunMigrations applies every pending .sql migration in migrationsDir
// against migrationsURL (the elevated, migration-time admin connection —
// never the app's own least-privilege DatabaseURL, which by design cannot
// CREATE TABLE/ROLE or REVOKE anything). Runs automatically at server
// startup (see main.go) rather than as a separate CLI step — this project
// is single-service, single-instance scale, and golang-migrate's postgres
// driver takes an advisory lock for the duration, so even an accidental
// concurrent local run is safe. A real multi-replica production rollout
// should switch to a pre-deploy migration step instead; not solved here,
// deliberately deferred (docs/DECISION_LOG.md, "Database setup: shared
// platform foundation + Audit on real Postgres").
//
// Idempotent: migrate.ErrNoChange (no pending migrations) is treated as
// success, not an error.
func RunMigrations(migrationsURL, migrationsDir string) error {
	fileURL, err := toFileURL(migrationsDir)
	if err != nil {
		return fmt.Errorf("platform: resolving migrations directory: %w", err)
	}
	m, err := migrate.New(fileURL, migrationsURL)
	if err != nil {
		return fmt.Errorf("platform: constructing migration runner: %w", err)
	}
	defer func() { _, _ = m.Close() }()

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("platform: running migrations: %w", err)
	}
	return nil
}

// ProvisionAppRolePassword sets AppDBRole's login password to password via
// a direct connection using migrationsURL (the admin connection). This is
// deliberately a Go-level step, separate from the .sql migration files: a
// migration file is committed to git, so a real secret must never be
// embedded in one. Migration 0001 creates AppDBRole with no password
// (`CREATE ROLE ascend_app LOGIN;`); this function is what actually makes
// it usable, immediately after migrations run, using a password sourced
// only from Config.AppDBPassword (an environment variable, never
// committed).
//
// Deliberately does NOT use a $1 parameter placeholder for the password:
// ALTER ROLE is a utility (DDL) statement, and PostgreSQL's extended query
// protocol does not support parameter placeholders inside utility
// statements the way it does for DML (SELECT/INSERT/UPDATE/DELETE) — this
// is a real, well-known PostgreSQL limitation ("there is no parameter $1"),
// not a design oversight. This is safe to build as a literal specifically
// BECAUSE both interpolated values are trusted, not attacker-reachable:
// AppDBRole is a fixed Go constant (never derived from any request), and
// password comes only from a local environment variable under the
// operator's own control — contrast with every business-logic query this
// service issues (e.g. audit's Query/Get), which handles genuinely
// caller-supplied values and therefore uses real $1..$N parameter binding
// throughout (see internal/audit/postgres_store.go). The password literal
// is still properly single-quote-escaped below, closing even the
// theoretical case of an unusual password value.
func ProvisionAppRolePassword(ctx context.Context, migrationsURL, password string) error {
	if password == "" {
		return errors.New("platform: app DB password must not be empty")
	}
	conn, err := pgx.Connect(ctx, migrationsURL)
	if err != nil {
		return fmt.Errorf("platform: connecting to provision app role password: %w", err)
	}
	defer func() { _ = conn.Close(ctx) }()

	stmt := fmt.Sprintf(`ALTER ROLE %s WITH LOGIN PASSWORD '%s'`, AppDBRole, escapePostgresLiteral(password))
	if _, err := conn.Exec(ctx, stmt); err != nil {
		return fmt.Errorf("platform: setting %s's password: %w", AppDBRole, err)
	}
	return nil
}

// escapePostgresLiteral escapes s for safe embedding inside a single-quoted
// Postgres string literal by doubling every single quote — the standard
// SQL escaping rule, sufficient because Postgres defaults to
// standard_conforming_strings=on (backslashes are not special).
func escapePostgresLiteral(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}
