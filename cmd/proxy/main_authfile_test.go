package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeAuthTokenFile writes an auth-token file for the PROXY_AUTH_TOKEN_FILE
// tests and returns its path. A real Secret mount delivers the token as a
// file in a read-only volume; a temp file is the same contract.
func writeAuthTokenFile(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "auth-token")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	return path
}

// TestResolveAuthToken_FileDeliversToken pins the file-based delivery path:
// PROXY_AUTH_TOKEN_FILE names a mounted Secret file and the bearer token never
// sits in the process environment, mirroring TUNNEL_TOKEN_FILE (MIR-1607).
func TestResolveAuthToken_FileDeliversToken(t *testing.T) {
	require.NoError(t, os.Unsetenv("PROXY_AUTH_TOKEN"))
	t.Setenv("PROXY_AUTH_TOKEN_FILE", writeAuthTokenFile(t, "a-real-bearer-token"))

	token, err := resolveAuthToken(authRequired)
	require.NoError(t, err)
	assert.Equal(t, "a-real-bearer-token", token)
}

// TestResolveAuthToken_FileTrimsTrailingNewline pins tolerance for the way
// tokens actually land in Secret files: `kubectl create secret --from-file`
// and heredocs routinely append a newline, which is not part of the token.
func TestResolveAuthToken_FileTrimsTrailingNewline(t *testing.T) {
	require.NoError(t, os.Unsetenv("PROXY_AUTH_TOKEN"))
	t.Setenv("PROXY_AUTH_TOKEN_FILE", writeAuthTokenFile(t, "a-real-bearer-token\n"))

	token, err := resolveAuthToken(authRequired)
	require.NoError(t, err)
	assert.Equal(t, "a-real-bearer-token", token)
}

// TestResolveAuthToken_FileAndEnvIsAmbiguous pins the refusal when both
// sources are wired: silently preferring one would let a stale env token keep
// authenticating pushes after the operator switched to (or rotated) the file,
// or vice versa. There is NO env fallback — two configured sources is a
// broken deployment, not a tie to break.
func TestResolveAuthToken_FileAndEnvIsAmbiguous(t *testing.T) {
	t.Setenv("PROXY_AUTH_TOKEN", "env-token")
	t.Setenv("PROXY_AUTH_TOKEN_FILE", writeAuthTokenFile(t, "file-token"))

	_, err := resolveAuthToken(authRequired)
	require.Error(t, err, "both PROXY_AUTH_TOKEN and PROXY_AUTH_TOKEN_FILE set must be refused")
	assert.ErrorIs(t, err, errProxyAuthTokenAmbiguous)
}

// TestResolveAuthToken_FileSetButEmptyIsBrokenConfig pins the same rule an
// empty PROXY_AUTH_TOKEN gets: present-but-empty signals authentication was
// intended and resolved to nothing, which is fatal — in BOTH modes, since an
// empty path would otherwise silently run standalone's config API open.
func TestResolveAuthToken_FileSetButEmptyIsBrokenConfig(t *testing.T) {
	require.NoError(t, os.Unsetenv("PROXY_AUTH_TOKEN"))
	t.Setenv("PROXY_AUTH_TOKEN_FILE", "")

	for _, requireAuth := range []configAPIAuth{authRequired, authOptional} {
		_, err := resolveAuthToken(requireAuth)
		require.Error(t, err, "an empty PROXY_AUTH_TOKEN_FILE must not silently disable config-API auth")
		assert.ErrorIs(t, err, errProxyAuthTokenFileEmpty)
	}
}

// TestResolveAuthToken_FileMissingIsBrokenConfig pins the unreadable-file
// case: a mount that did not land (wrong Secret name, missing key) must fail
// the start, not fall back to an unauthenticated config API.
func TestResolveAuthToken_FileMissingIsBrokenConfig(t *testing.T) {
	require.NoError(t, os.Unsetenv("PROXY_AUTH_TOKEN"))
	t.Setenv("PROXY_AUTH_TOKEN_FILE", filepath.Join(t.TempDir(), "does-not-exist"))

	_, err := resolveAuthToken(authRequired)
	require.Error(t, err, "an unreadable auth-token file must fail the start")
}

// TestResolveAuthToken_FileWithEmptyContentIsBrokenConfig pins the
// file-delivery twin of errProxyAuthTokenEmpty: a mounted file holding
// nothing (an empty Secret key) is a broken configuration, not a choice to
// run the config API open.
func TestResolveAuthToken_FileWithEmptyContentIsBrokenConfig(t *testing.T) {
	require.NoError(t, os.Unsetenv("PROXY_AUTH_TOKEN"))
	t.Setenv("PROXY_AUTH_TOKEN_FILE", writeAuthTokenFile(t, "\n"))

	_, err := resolveAuthToken(authRequired)
	require.Error(t, err, "an empty auth-token file must not silently disable config-API auth")
	assert.ErrorIs(t, err, errProxyAuthTokenEmpty)
}

// TestResolveAuthToken_FileEmptyIsBrokenEvenWhenAcknowledged pins that the
// unauthenticated-config-API escape hatch does not cover a broken Secret
// file, exactly as it does not cover an empty PROXY_AUTH_TOKEN: the
// acknowledgement says "run without authentication"; an empty file says
// "authentication was wired and resolved to nothing".
func TestResolveAuthToken_FileEmptyIsBrokenEvenWhenAcknowledged(t *testing.T) {
	require.NoError(t, os.Unsetenv("PROXY_AUTH_TOKEN"))
	t.Setenv("PROXY_AUTH_TOKEN_FILE", writeAuthTokenFile(t, ""))
	t.Setenv(allowUnauthenticatedConfigAPIEnv, "1")

	_, err := resolveAuthToken(authRequired)
	require.Error(t, err)
	assert.ErrorIs(t, err, errProxyAuthTokenEmpty)
}
