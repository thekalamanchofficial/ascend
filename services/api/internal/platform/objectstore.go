package platform

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// S3Config is the subset of Config needed to construct an S3-compatible
// client — narrowed here (rather than passing the whole Config) so this
// file's dependency on the rest of Config's fields stays explicit and
// minimal.
type S3Config struct {
	Endpoint     string
	Bucket       string
	AccessKey    string
	SecretKey    string
	Region       string
	UsePathStyle bool
}

// NewS3Client constructs an S3-compatible object-storage client against
// cfg.Endpoint with a custom base endpoint and static credentials — this
// works unchanged against MinIO locally (path-style required) and
// DigitalOcean Spaces or real S3 in production later; only the env vars
// feeding S3Config change, never this code. Confirms the configured bucket
// is actually reachable via HeadBucket before returning, so a
// misconfigured endpoint/bucket/credential fails at startup, matching this
// package's other constructors' fail-fast discipline.
//
// Nothing consumes this client yet as of this pass (see wiring.go) — it is
// constructed and health-checked purely to prove the shared foundation
// works end to end. A future pass wires Storage's blob backend onto it
// (services/api/internal/storage/backend.go's Backend interface already
// exists as the seam for this — see that file's own doc comment).
func NewS3Client(ctx context.Context, cfg S3Config) (*s3.Client, error) {
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(cfg.Region),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(cfg.AccessKey, cfg.SecretKey, "")),
	)
	if err != nil {
		return nil, fmt.Errorf("platform: loading S3 client config: %w", err)
	}

	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(cfg.Endpoint)
		o.UsePathStyle = cfg.UsePathStyle
	})

	checkCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if _, err := client.HeadBucket(checkCtx, &s3.HeadBucketInput{Bucket: aws.String(cfg.Bucket)}); err != nil {
		return nil, fmt.Errorf("platform: confirming S3 bucket %q is reachable at %q: %w", cfg.Bucket, cfg.Endpoint, err)
	}
	return client, nil
}
