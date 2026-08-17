package platform

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// NewRedisClient constructs a Redis client against redisURL and pings it
// before returning, so a bad connection string or unreachable Redis fails
// at construction time — same fail-fast discipline as NewPostgresPool.
//
// Nothing consumes this client yet as of this pass (see wiring.go's own
// comment on this) — it is constructed and health-checked at startup
// purely to prove the shared foundation genuinely works end to end. Redis
// is scoped, by design (docs/DECISION_LOG.md, "Database setup: shared
// platform foundation + Audit on real Postgres"), to purely ephemeral state
// with no durability/export requirement — Session/Request Authentication's
// challenge nonces and future rate-limiting counters, once a later pass
// wires either onto it. Session tokens themselves are NOT a Redis
// candidate: ExportSessions must be able to show expired-but-not-yet-
// revoked sessions, which a pure Redis TTL would evict and lose.
func NewRedisClient(ctx context.Context, redisURL string) (*redis.Client, error) {
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("platform: parsing REDIS_URL: %w", err)
	}
	client := redis.NewClient(opts)

	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := client.Ping(pingCtx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("platform: pinging redis: %w", err)
	}
	return client, nil
}
