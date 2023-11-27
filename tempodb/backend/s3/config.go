package s3

import (
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/grafana/dskit/crypto/tls"
	"github.com/grafana/dskit/flagext"

	"github.com/grafana/tempo/pkg/util"
)

const (
	// SSEKMS config type constant to configure S3 server side encryption using KMS
	// https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingKMSEncryption.html
	SSEKMS = "SSE-KMS"

	// SSEC is the name of the SSE-C method for objstore encryption.
	// https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerSideEncryptionCustomerKeys.html
	SSEC = "SSE-C"

	// SSES3 config type constant to configure S3 server side encryption with AES-256
	// https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingServerSideEncryption.html
	SSES3 = "SSE-S3"
)

var supportedSSETypes = []string{SSEKMS, SSES3, SSEC}

type Config struct {
	tls.ClientConfig `yaml:",inline"`

	Bucket            string         `yaml:"bucket"`
	Prefix            string         `yaml:"prefix"`
	Endpoint          string         `yaml:"endpoint"`
	Region            string         `yaml:"region"`
	AccessKey         string         `yaml:"access_key"`
	SecretKey         flagext.Secret `yaml:"secret_key"`
	SessionToken      flagext.Secret `yaml:"session_token"`
	Insecure          bool           `yaml:"insecure"`
	PartSize          uint64         `yaml:"part_size"`
	HedgeRequestsAt   time.Duration  `yaml:"hedge_requests_at"`
	HedgeRequestsUpTo int            `yaml:"hedge_requests_up_to"`
	// SignatureV2 configures the object storage to use V2 signing instead of V4
	SignatureV2      bool              `yaml:"signature_v2"`
	ForcePathStyle   bool              `yaml:"forcepathstyle"`
	BucketLookupType int               `yaml:"bucket_lookup_type"`
	Tags             map[string]string `yaml:"tags"`
	StorageClass     string            `yaml:"storage_class"`
	Metadata         map[string]string `yaml:"metadata"`

	SSE SSEConfig `yaml:"sse"`
	// Deprecated
	// See https://github.com/grafana/tempo/pull/3006 for more details
	NativeAWSAuthEnabled bool `yaml:"native_aws_auth_enabled"`
}

func (cfg *Config) RegisterFlagsAndApplyDefaults(prefix string, f *flag.FlagSet) {
	f.StringVar(&cfg.Bucket, util.PrefixConfig(prefix, "s3.bucket"), "", "s3 bucket to store blocks in.")
	f.StringVar(&cfg.Prefix, util.PrefixConfig(prefix, "s3.prefix"), "", "s3 root directory to store blocks in.")
	f.StringVar(&cfg.Endpoint, util.PrefixConfig(prefix, "s3.endpoint"), "", "s3 endpoint to push blocks to.")
	f.StringVar(&cfg.AccessKey, util.PrefixConfig(prefix, "s3.access_key"), "", "s3 access key.")
	f.StringVar(&cfg.MinVersion, util.PrefixConfig(prefix, "s3.tls_min_version"), "VersionTLS12", "minimum version of TLS to use when connecting to s3.")
	f.Var(&cfg.SecretKey, util.PrefixConfig(prefix, "s3.secret_key"), "s3 secret key.")
	f.Var(&cfg.SessionToken, util.PrefixConfig(prefix, "s3.session_token"), "s3 session token.")
	cfg.SSE.RegisterFlagsWithPrefix(prefix+"s3.sse.", f)
	cfg.HedgeRequestsUpTo = 2
}

// SSEConfig configures S3 server side encryption
// struct that is going to receive user input (through config file or CLI)
type SSEConfig struct {
	Type                 string `yaml:"type"`
	KMSKeyID             string `yaml:"kms_key_id"`
	KMSEncryptionContext string `yaml:"kms_encryption_context"`
	EncryptionKey        string `yaml:"encryption_key"`
}

// RegisterFlagsWithPrefix adds the flags required to config this to the given FlagSet
func (cfg *SSEConfig) RegisterFlagsWithPrefix(prefix string, f *flag.FlagSet) {
	f.StringVar(&cfg.Type, prefix+"type", "", fmt.Sprintf("Enable AWS Server Side Encryption. Supported values: %s.", strings.Join(supportedSSETypes, ", ")))
	f.StringVar(&cfg.KMSKeyID, prefix+"kms-key-id", "", "KMS Key ID used to encrypt objects in S3")
	f.StringVar(&cfg.KMSEncryptionContext, prefix+"kms-encryption-context", "", "KMS Encryption Context used for object encryption. It expects JSON formatted string.")
	f.StringVar(&cfg.EncryptionKey, prefix+"encryption-key", "", "TODO")
}

func (cfg *Config) PathMatches(other *Config) bool {
	// S3 bucket names are globally unique
	return cfg.Bucket == other.Bucket && cfg.Prefix == other.Prefix
}
