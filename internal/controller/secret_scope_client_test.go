package controller

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// errAPIServerDown is an unrelated failure for the pass-through case. The
// out-of-scope errors themselves are NOT hand-copied here: the tests below
// read through a real controller-runtime cache (newScopedSecretCacheAndClient,
// secret_scope_client_realcache_test.go), so a controller-runtime upgrade that
// rewords the cache's error breaks them instead of passing silently.
var errAPIServerDown = errors.New("the apiserver is on fire")

// TestSecretScopeClient_OutOfScopeReadIsNotFound pins the error contract the
// scoped Secret cache needs (MIR-1607): the multi-namespace cache reports a
// read outside its namespace set as a PLAIN error, which every Secret
// consumer classifies as transient — a single Gateway referencing an
// out-of-scope Secret would then stall its whole partition's config push and
// requeue forever. The wrapper turns it into a deterministic NotFound, so the
// reference is refused and isolated exactly like a missing Secret, with the
// remedy in the message. The read goes through a real scoped cache built with
// cache.New, exactly as the manager wires it.
func TestSecretScopeClient_OutOfScopeReadIsNotFound(t *testing.T) {
	t.Parallel()

	key := types.NamespacedName{Namespace: "unlisted", Name: "edge-cert"}

	_, wrapped := newScopedSecretCacheAndClient(t, "listed")

	err := wrapped.Get(context.Background(), key, &corev1.Secret{})
	require.Error(t, err)
	assert.True(t, apierrors.IsNotFound(err),
		"an out-of-scope read must be a deterministic NotFound, not a transient error")
	assert.Contains(t, err.Error(), "unlisted", "the message must name the out-of-scope namespace")
	assert.Contains(t, err.Error(), "extraSecretNamespaces", "the message must carry the remedy")
}

// TestSecretScopeClient_OtherErrorsAndHitsPassThrough pins the wrapper's
// transparency: a real read works, a NotFound stays a NotFound, and an
// unrelated failure keeps its transient classification.
func TestSecretScopeClient_OtherErrorsAndHitsPassThrough(t *testing.T) {
	t.Parallel()

	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "tok", Namespace: "listed"}}
	inner := fake.NewClientBuilder().WithObjects(secret).Build()
	wrapped := &secretScopeClient{Client: inner}

	var got corev1.Secret
	require.NoError(t, wrapped.Get(context.Background(), types.NamespacedName{Namespace: "listed", Name: "tok"}, &got))

	err := wrapped.Get(context.Background(), types.NamespacedName{Namespace: "listed", Name: "absent"}, &got)
	assert.True(t, apierrors.IsNotFound(err))

	boom := fake.NewClientBuilder().WithInterceptorFuncs(interceptor.Funcs{
		Get: func(_ context.Context, _ client.WithWatch, _ client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
			return errAPIServerDown
		},
	}).Build()
	wrapped = &secretScopeClient{Client: boom}

	err = wrapped.Get(context.Background(), types.NamespacedName{Namespace: "listed", Name: "tok"}, &got)
	require.Error(t, err)
	assert.False(t, apierrors.IsNotFound(err), "a genuine failure must stay transient")
}

// TestSecretScopeMessage pins the marker contract consumers rely on
// (MIR-1676): the converted NotFound carries a detectable cause, and
// secretScopeMessage recovers its diagnostic — through wrapping — while
// refusing a plain NotFound, so "outside the watched namespaces" is never
// reported for a Secret that is genuinely absent.
func TestSecretScopeMessage(t *testing.T) {
	t.Parallel()

	scopeErr := outOfScopeSecretError("unlisted", "edge-cert")

	msg, ok := secretScopeMessage(scopeErr)
	require.True(t, ok, "the converted out-of-scope error must be recognised")
	assert.Contains(t, msg, `namespace "unlisted"`)
	assert.Contains(t, msg, "extraSecretNamespaces", "the diagnostic must carry the remedy")

	msg, ok = secretScopeMessage(fmt.Errorf("reading Secret: %w", scopeErr))
	require.True(t, ok, "wrapping must not hide the marker (errors.As)")
	assert.Contains(t, msg, "extraSecretNamespaces")

	_, ok = secretScopeMessage(apierrors.NewNotFound(corev1.Resource(secretsResource), "edge-cert"))
	assert.False(t, ok, "a plain NotFound (Secret genuinely absent) must not match")

	_, ok = secretScopeMessage(errAPIServerDown)
	assert.False(t, ok, "a non-status error must not match")

	_, ok = secretScopeMessage(nil)
	assert.False(t, ok)
}

// TestMissingSecretMessage_BoundaryLength pins the condition-message cap
// (maxConditionMessageLength, 256) on the scope diagnostic: with a
// maximum-length namespace (63) and Secret name (253) the message stays
// within the cap, and because the remedy precedes the variable-length name,
// the cut can only ever eat the name — never the namespace or the
// extraSecretNamespaces remedy.
func TestMissingSecretMessage_BoundaryLength(t *testing.T) {
	t.Parallel()

	longNS := strings.Repeat("n", 63)
	longName := strings.Repeat("s", 253)

	msg := missingSecretMessage(outOfScopeSecretError(longNS, longName), longNS, longName)
	assert.LessOrEqual(t, len(msg), maxConditionMessageLength)
	assert.Contains(t, msg, longNS, "the namespace must survive the cap")
	assert.Contains(t, msg, "extraSecretNamespaces", "the remedy must survive the cap")

	// A plain NotFound keeps the existing not-found text, and is capped the
	// same way at boundary lengths (there the trailing "not found" is what
	// the cut eats — pre-existing phrasing, and the reason still says
	// InvalidCertificateRef).
	plain := missingSecretMessage(apierrors.NewNotFound(corev1.Resource(secretsResource), "edge-cert"), "unlisted", "edge-cert")
	assert.Equal(t, "Secret unlisted/edge-cert not found", plain)

	longPlain := missingSecretMessage(apierrors.NewNotFound(corev1.Resource(secretsResource), longName), longNS, longName)
	assert.LessOrEqual(t, len(longPlain), maxConditionMessageLength)
}

// TestSecretScopeClient_ConvertedErrorCarriesMarker pins that the wrapper's
// own conversion path produces the marked error secretScopeMessage detects —
// the constructor and the Get/List paths cannot drift apart.
func TestSecretScopeClient_ConvertedErrorCarriesMarker(t *testing.T) {
	t.Parallel()

	// A real scoped cache produces the out-of-scope error (MIR-1691), so this
	// pins the conversion against controller-runtime's actual message.
	_, wrapped := newScopedSecretCacheAndClient(t, "listed")

	err := wrapped.Get(context.Background(), types.NamespacedName{Namespace: "unlisted", Name: "edge-cert"}, &corev1.Secret{})
	require.Error(t, err)

	msg, ok := secretScopeMessage(err)
	require.True(t, ok, "the Get conversion must carry the out-of-scope marker")
	assert.Contains(t, msg, "extraSecretNamespaces")
}

// TestSecretScopeClient_ListConversion pins the same contract for List, which
// the real multi-namespace cache refuses with the sibling message.
func TestSecretScopeClient_ListConversion(t *testing.T) {
	t.Parallel()

	_, wrapped := newScopedSecretCacheAndClient(t, "listed")

	err := wrapped.List(context.Background(), &corev1.SecretList{}, client.InNamespace("unlisted"))
	require.Error(t, err)
	assert.True(t, apierrors.IsNotFound(err))
}
