package controller

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestSecretCacheNamespaces pins the scoped-cache construction (MIR-1607):
// empty keeps the cluster-wide cache (nil), a configured list is honoured
// verbatim, and the controller's own namespace is always folded in — the
// startup-critical Secrets (generated auth token, config TLS CA and leaf)
// live there, and a list that omitted it would brick the controller rather
// than scope it.
func TestSecretCacheNamespaces(t *testing.T) {
	t.Setenv("CONTROLLER_NAMESPACE", "cf-system")

	assert.Nil(t, secretCacheNamespaces(nil), "no list keeps the cluster-wide cache")
	assert.Nil(t, secretCacheNamespaces([]string{}), "no list keeps the cluster-wide cache")

	scoped := secretCacheNamespaces([]string{"tenant-a", " tenant-b ", ""})
	assert.Len(t, scoped, 3)
	assert.Contains(t, scoped, "tenant-a")
	assert.Contains(t, scoped, "tenant-b", "entries are trimmed, not dropped")
	assert.Contains(t, scoped, "cf-system", "the controller's own namespace is always included")
}
