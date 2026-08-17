package platform

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// maxPoolConns bounds the connection pool this service opens against
// Postgres. A documented constant, not hidden magic — conservative for a
// single-instance dev/first-pass deployment; revisit deliberately if a real
// multi-instance rollout needs it raised.
const maxPoolConns = 10

// NewPostgresPool constructs a pgx connection pool against databaseURL and
// pings it before returning, so a bad connection string or unreachable
// database fails at construction time (a single, clear startup error) —
// never on the first query a request happens to trigger, matching this
// service's existing fail-fast-on-construction-error precedent
// (services/api/main.go's log.Fatalf on Storage/File Objects construction
// errors).
func NewPostgresPool(ctx context.Context, databaseURL string) (*pgxpool.Pool, error) {
	poolCfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("platform: parsing DATABASE_URL: %w", err)
	}
	poolCfg.MaxConns = maxPoolConns

	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("platform: constructing postgres pool: %w", err)
	}
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("platform: pinging postgres: %w", err)
	}
	return pool, nil
}
