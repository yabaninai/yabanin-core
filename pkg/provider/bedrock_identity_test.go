// Package provider — AWS identity-chain contract tests for the native
// Bedrock adapter (N08-P02-T03).
//
// Card contract: a static access key must NOT be required. Identity is the
// AWS SDK DefaultChain via config.LoadDefaultConfig — environment
// credentials (incl. AWS_SESSION_TOKEN temporary credentials), shared
// credentials/config files with AWS_PROFILE selection, credential_process
// external helpers, and the SDK-owned IMDS / web identity / SSO / container
// credential legs. The adapter constructor never demands identity; identity
// absence fails closed at request time with a deterministic adapter-owned
// error.
//
// Hermeticity: every test strips the ambient machine environment (the dev
// stand may carry a real ~/.aws or SSO session) by pointing
// AWS_CONFIG_FILE / AWS_SHARED_CREDENTIALS_FILE at empty temp fixtures and
// disabling IMDS, so the DefaultChain resolves ONLY what a test installs.
// t.Setenv forbids t.Parallel, so identity tests are sequential by
// construction (same convention as the wire tests). The IMDS / web identity
// / SSO legs terminate in live AWS endpoints and cannot be exercised
// offline — the live-smoke file documents that loud-skip.
package provider

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// bedrockAWSIdentityEnvVars enumerates every environment variable that can
// feed the DefaultChain identity or redirect its endpoints. All are blanked
// (empty value = unset for the SDK) before a test installs its own fixture.
var bedrockAWSIdentityEnvVars = []string{
	"AWS_ACCESS_KEY_ID",
	"AWS_SECRET_ACCESS_KEY",
	"AWS_SESSION_TOKEN",
	"AWS_REGION",
	"AWS_DEFAULT_REGION",
	"AWS_PROFILE",
	"AWS_CONFIG_FILE",
	"AWS_SHARED_CREDENTIALS_FILE",
	"AWS_WEB_IDENTITY_TOKEN_FILE",
	"AWS_ROLE_ARN",
	"AWS_ROLE_SESSION_NAME",
	"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
	"AWS_CONTAINER_CREDENTIALS_FULL_URI",
	"AWS_ENDPOINT_URL",
	"AWS_ENDPOINT_URL_STS",
	"AWS_ENDPOINT_URL_SSO",
	"AWS_EC2_METADATA_DISABLED",
}

// bedrockIsolateAWSIdentity blanks every ambient AWS identity source and
// points the shared config/credentials files at empty temp fixtures, so the
// DefaultChain resolves only what the test installs afterwards. IMDS is
// disabled: the probe is skipped (fast, deterministic) both when a test
// installs identity (chain stops earlier) and when it does not.
func bedrockIsolateAWSIdentity(t *testing.T) {
	t.Helper()
	for _, k := range bedrockAWSIdentityEnvVars {
		t.Setenv(k, "")
	}
	dir := t.TempDir()
	for _, name := range []string{"config", "credentials"} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), nil, 0o600))
	}
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(dir, "config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(dir, "credentials"))
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
}

// bedrockWriteSharedFile writes a shared config/credentials fixture and
// points the corresponding env var at it.
func bedrockWriteSharedFile(t *testing.T, envVar, name, content string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	t.Setenv(envVar, path)
}

// bedrockSignThroughDefaultChain runs one full request construction through
// the PRODUCTION constructor (no injected config): TranslateRequest →
// PrepareRequest against an explicit base URL. Returns the Authorization
// header and the security-token header so tests can pin chain identity.
func bedrockSignThroughDefaultChain(t *testing.T, openaiBody string) (authorization, securityToken string) {
	t.Helper()
	b := NewBedrock() // production constructor: DefaultChain, lazy, no static-key requirement
	out, err := b.TranslateRequest([]byte(openaiBody))
	require.NoError(t, err)
	req, err := b.PrepareRequest(context.Background(), "https://bedrock-runtime.test.local", "", out, "", false)
	require.NoError(t, err)
	return req.Header.Get("Authorization"), req.Header.Get("X-Amz-Security-Token")
}

// TestBedrockIdentityChain_ConstructorRequiresNoIdentity pins the core card
// contract: the production constructor succeeds with ZERO identity sources
// (no static key required, nothing probed at construction) and the failure
// surfaces only at request time, failing closed with the adapter-owned
// diagnostic. A region is installed so the CREDENTIAL leg is the one that
// fails — with no region either, the region check fires first (fail-closed
// order: envelope → config → region → credentials → sign).
func TestBedrockIdentityChain_ConstructorRequiresNoIdentity(t *testing.T) {
	bedrockIsolateAWSIdentity(t)
	t.Setenv("AWS_REGION", "us-east-1")

	b := NewBedrock() // must not error, must not probe the network
	assert.Equal(t, "bedrock", b.Name())

	out, err := b.TranslateRequest([]byte(bedrockOpenaiBody))
	require.NoError(t, err)
	_, err = b.PrepareRequest(context.Background(), "https://bedrock.example.com", "", out, "", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bedrock:")
	assert.Contains(t, err.Error(), "credential")
	// Fail-closed caching: the broken environment fails deterministically on
	// every subsequent request (no flaky per-hop probing).
	_, err = b.PrepareRequest(context.Background(), "https://bedrock.example.com", "", out, "", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bedrock:")
}

// TestBedrockIdentityChain_EnvTemporaryCredentials proves the env leg
// accepts AWS temporary credentials (access key + secret + session token):
// the session token must travel as X-Amz-Security-Token in the SigV4
// signature, not as any static bearer/api key.
func TestBedrockIdentityChain_EnvTemporaryCredentials(t *testing.T) {
	bedrockIsolateAWSIdentity(t)
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDTEMPTOKEN")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "temp-key-material")
	t.Setenv("AWS_SESSION_TOKEN", "temporary-session-token-value")
	t.Setenv("AWS_REGION", "us-east-2")

	auth, securityToken := bedrockSignThroughDefaultChain(t, bedrockOpenaiBody)
	assert.Contains(t, auth, "AWS4-HMAC-SHA256 Credential=AKIDTEMPTOKEN/")
	assert.Contains(t, auth, "/us-east-2/"+bedrockSigningName+"/aws4_request")
	assert.Equal(t, "temporary-session-token-value", securityToken)
	assert.NotContains(t, auth, "Bearer")
}

// TestBedrockIdentityChain_DefaultRegionFallback proves the region leg of
// the chain: AWS_DEFAULT_REGION is honored when AWS_REGION is unset.
func TestBedrockIdentityChain_DefaultRegionFallback(t *testing.T) {
	bedrockIsolateAWSIdentity(t)
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDDEFREGION")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "default-region-key")
	t.Setenv("AWS_DEFAULT_REGION", "eu-west-1")

	auth, _ := bedrockSignThroughDefaultChain(t, bedrockOpenaiBody)
	assert.Contains(t, auth, "/eu-west-1/"+bedrockSigningName+"/aws4_request")
}

// TestBedrockIdentityChain_SharedCredentialsProfile proves the shared
// credentials file leg with explicit AWS_PROFILE selection (no env keys at
// all): identity comes from [deploy] in the credentials file.
func TestBedrockIdentityChain_SharedCredentialsProfile(t *testing.T) {
	bedrockIsolateAWSIdentity(t)
	bedrockWriteSharedFile(t, "AWS_SHARED_CREDENTIALS_FILE", "credentials", `
[deploy]
aws_access_key_id = AKIDPROFILEDEPLOY
aws_secret_access_key = deploy-profile-key
`)
	t.Setenv("AWS_PROFILE", "deploy")
	// Region is a separate chain leg (proven by the config-file row below);
	// credentials-file profiles carry no region, so pin one via env here.
	t.Setenv("AWS_REGION", "us-east-2")

	auth, securityToken := bedrockSignThroughDefaultChain(t, bedrockOpenaiBody)
	assert.Contains(t, auth, "AWS4-HMAC-SHA256 Credential=AKIDPROFILEDEPLOY/")
	assert.Contains(t, auth, "/us-east-2/"+bedrockSigningName+"/aws4_request")
	assert.Empty(t, securityToken, "long-lived profile credentials carry no session token")
}

// TestBedrockIdentityChain_SharedCredentialsDefaultProfile proves the same
// leg WITHOUT AWS_PROFILE: the [default] section is the fallback profile.
func TestBedrockIdentityChain_SharedCredentialsDefaultProfile(t *testing.T) {
	bedrockIsolateAWSIdentity(t)
	bedrockWriteSharedFile(t, "AWS_SHARED_CREDENTIALS_FILE", "credentials", `
[default]
aws_access_key_id = AKIDDEFAULTPROFILE
aws_secret_access_key = default-profile-key
`)
	t.Setenv("AWS_REGION", "us-east-2")

	auth, _ := bedrockSignThroughDefaultChain(t, bedrockOpenaiBody)
	assert.Contains(t, auth, "AWS4-HMAC-SHA256 Credential=AKIDDEFAULTPROFILE/")
}

// TestBedrockIdentityChain_ConfigFileRegionAndProfile proves the shared
// CONFIG file leg: region resolved from [profile ops] (never from ambient
// env — it is blanked), identity from the matching credentials section.
func TestBedrockIdentityChain_ConfigFileRegionAndProfile(t *testing.T) {
	bedrockIsolateAWSIdentity(t)
	bedrockWriteSharedFile(t, "AWS_CONFIG_FILE", "config", `
[profile ops]
region = ap-southeast-2
output = json
`)
	bedrockWriteSharedFile(t, "AWS_SHARED_CREDENTIALS_FILE", "credentials", `
[ops]
aws_access_key_id = AKIDPROFILEOPS
aws_secret_access_key = ops-profile-key
`)
	t.Setenv("AWS_PROFILE", "ops")

	auth, _ := bedrockSignThroughDefaultChain(t, bedrockOpenaiBody)
	assert.Contains(t, auth, "AWS4-HMAC-SHA256 Credential=AKIDPROFILEOPS/")
	assert.Contains(t, auth, "/ap-southeast-2/"+bedrockSigningName+"/aws4_request")
}

// TestBedrockIdentityChain_CredentialProcess proves the dynamic identity
// leg: credential_process runs an external helper (how SSO/IMDS-less
// machines and vault integrations resolve identity) and the resolved
// credentials sign the request. The helper here is /bin/sh over a data-file
// fixture — deterministic, offline, no executable-bit games.
func TestBedrockIdentityChain_CredentialProcess(t *testing.T) {
	bedrockIsolateAWSIdentity(t)
	script := filepath.Join(t.TempDir(), "creds.sh")
	require.NoError(t, os.WriteFile(script, []byte(
		`#!/bin/sh
echo '{"Version":1,"AccessKeyId":"AKIDPROCESSCHAIN","SecretAccessKey":"process-helper-key"}'
`), 0o600))
	bedrockWriteSharedFile(t, "AWS_CONFIG_FILE", "config",
		"[default]\ncredential_process = /bin/sh "+script+"\n")
	t.Setenv("AWS_REGION", "us-east-2") // region leg is proven separately

	auth, _ := bedrockSignThroughDefaultChain(t, bedrockOpenaiBody)
	assert.Contains(t, auth, "AWS4-HMAC-SHA256 Credential=AKIDPROCESSCHAIN/")
}

// TestBedrockIdentityChain_RegionRequiredWithIdentity proves the region leg
// fails closed with the operator-guided error when identity resolves but no
// region source exists (through the production chain, not an injected
// config).
func TestBedrockIdentityChain_RegionRequiredWithIdentity(t *testing.T) {
	bedrockIsolateAWSIdentity(t)
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDNOREGION")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "no-region-key")

	b := NewBedrock()
	out, err := b.TranslateRequest([]byte(bedrockOpenaiBody))
	require.NoError(t, err)
	_, err = b.PrepareRequest(context.Background(), "https://bedrock.example.com", "", out, "", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "region is not configured")
}

// TestBedrockIdentityChain_InjectedConfigBypassesEnv pins the NewBedrockWithConfig
// seam: an injected aws.Config (custom Credentials provider / region) is
// used verbatim and ambient env identity is ignored — the test-injection
// hook the wire tests rely on.
func TestBedrockIdentityChain_InjectedConfigBypassesEnv(t *testing.T) {
	bedrockIsolateAWSIdentity(t)
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDAMBIENTSHADOW")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "ambient-key-that-must-lose")
	t.Setenv("AWS_REGION", "us-east-1")

	b := NewBedrockWithConfig(aws.Config{Region: "sa-east-1", Credentials: bedrockStubCreds{}})
	out, err := b.TranslateRequest([]byte(bedrockOpenaiBody))
	require.NoError(t, err)
	req, err := b.PrepareRequest(context.Background(), "https://bedrock.example.com", "", out, "", false)
	require.NoError(t, err)
	auth := req.Header.Get("Authorization")
	assert.Contains(t, auth, "/sa-east-1/"+bedrockSigningName+"/aws4_request")
	assert.NotContains(t, auth, "AKIDAMBIENTSHADOW",
		"injected config must win over ambient env (test determinism)")
}

// TestBedrockIdentityChain_EnvVarsDoNotLeakIntoErrors pins the security
// invariant: no identity fixture value (key material, session token, helper
// output) ever appears in adapter error strings. Uses a failed request
// (missing region) with maximally recognizable values.
func TestBedrockIdentityChain_EnvVarsDoNotLeakIntoErrors(t *testing.T) {
	bedrockIsolateAWSIdentity(t)
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDLEAKCHECK")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "leakcheck-key-material")
	t.Setenv("AWS_SESSION_TOKEN", "leakcheck-session-token")

	b := NewBedrock()
	out, err := b.TranslateRequest([]byte(bedrockOpenaiBody))
	require.NoError(t, err)
	_, err = b.PrepareRequest(context.Background(), "https://bedrock.example.com", "", out, "", false)
	require.Error(t, err) // no region configured
	msg := err.Error()
	assert.NotContains(t, msg, "AKIDLEAKCHECK")
	assert.NotContains(t, msg, "leakcheck-key-material")
	assert.NotContains(t, msg, "leakcheck-session-token")
	assert.NotContains(t, msg, "AWS_SECRET_ACCESS_KEY=")
}
