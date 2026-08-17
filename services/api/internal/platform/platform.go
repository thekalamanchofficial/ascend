package platform

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

// Platform bundles every shared infrastructure client this service's
// composition root constructs once at startup: the Postgres pool (the
// app's own least-privilege connection, per Config.DatabaseURL — never the
// migration-time admin connection, which is used only transiently during
// startup and held nowhere after that), the Redis client, and the
// S3-compatible object-storage client. One object for main.go to hold and
// defer-close, rather than three separate ad hoc variables.
type Platform struct {
	DB    *pgxpool.Pool
	Redis *redis.Client
	S3    *s3.Client
}

// New runs migrations (using cfg.MigrationsDatabaseURL), provisions
// AppDBRole's password (using cfg.AppDBPassword), then constructs and
// health-checks the Postgres pool (using cfg.DatabaseURL — the
// least-privilege app connection), Redis client, and S3 client, in that
// order. Every step fails fast (a wrapped error, never a panic or a silent
// partial result) — the composition root (main.go) is expected to
// log.Fatalf on any error this returns, matching this service's existing
// construction-error precedent.
func New(ctx context.Context, cfg Config) (*Platform, error) {
	if err := RunMigrations(cfg.MigrationsDatabaseURL, migrationsDir); err != nil {
		return nil, fmt.Errorf("platform: %w", err)
	}
	if err := ProvisionAppRolePassword(ctx, cfg.MigrationsDatabaseURL, cfg.AppDBPassword); err != nil {
		return nil, fmt.Errorf("platform: %w", err)
	}

	pool, err := NewPostgresPool(ctx, cfg.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("platform: %w", err)
	}

	redisClient, err := NewRedisClient(ctx, cfg.RedisURL)
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("platform: %w", err)
	}

	s3Client, err := NewS3Client(ctx, S3Config{
		Endpoint:     cfg.S3Endpoint,
		Bucket:       cfg.S3Bucket,
		AccessKey:    cfg.S3AccessKey,
		SecretKey:    cfg.S3SecretKey,
		Region:       cfg.S3Region,
		UsePathStyle: cfg.S3UsePathStyle,
	})
	if err != nil {
		pool.Close()
		_ = redisClient.Close()
		return nil, fmt.Errorf("platform: %w", err)
	}

	return &Platform{DB: pool, Redis: redisClient, S3: s3Client}, nil
}

// Close tears down every held client. Safe to call once, at process
// shutdown (main.go defers this immediately after a successful New).
func (p *Platform) Close() {
	if p == nil {
		return
	}
	if p.DB != nil {
		p.DB.Close()
	}
	if p.Redis != nil {
		_ = p.Redis.Close()
	}
	// s3.Client holds no closable connection/resource of its own (it's a
	// stateless HTTP-request-per-call client) — nothing to close.
}

// migrationsDir is fixed relative to this package's own source location
// (mirrors services/api/internal/storage/backend.go's DefaultDataDir
// pattern for the same reason: behavior must be identical regardless of
// where `go run`/the compiled binary is launched from) rather than the
// process's current working directory.
var migrationsDir = defaultMigrationsDir()
