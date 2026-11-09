package config

// Onprem toggles external vs bundled stateful services for air-gap deploys.
// Zero-value (ExternalPostgres=false) = bundled/SaaS default (back-compat).
type Onprem struct {
	ExternalPostgres bool   `yaml:"external_postgres"` // true = use pg_uri, skip bundled statefulset
	ExternalRedis    bool   `yaml:"external_redis"`
	BlobStore        string `yaml:"blob_store"`  // "s3" | "minio" | "local"
	S3Endpoint       string `yaml:"s3_endpoint"` // MinIO or AWS S3
	S3Bucket         string `yaml:"s3_bucket"`
	S3Region         string `yaml:"s3_region"`
	S3AccessKey      string `yaml:"s3_access_key"` // empty = IAM role
	S3SecretKey      string `yaml:"s3_secret_key"`
	S3UsePathStyle   bool   `yaml:"s3_use_path_style"` // true for MinIO
	S3LocalPath      string `yaml:"s3_local_path"`     // for provider="local"
	KEKPath          string `yaml:"kek_path"`          // file-based KMS key encryption key path
}
