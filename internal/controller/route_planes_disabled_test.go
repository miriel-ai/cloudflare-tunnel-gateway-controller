package controller

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lexfrei/cloudflare-tunnel-gateway-controller/internal/cfmetrics"
	"github.com/lexfrei/cloudflare-tunnel-gateway-controller/internal/config"
)

// TestResolveInfraGateways_PlanesDisabledRefusesWithoutResolving pins the
// route-sync half of --per-gateway-data-planes=false: every opted-in Gateway
// is refused (its routes are served from NO partition, never silently from
// the shared plane), and the refusal is decided without resolving the
// Gateway's GatewayConfig — its token Secret lives in a namespace the scoped
// Secret cache cannot read, so a resolve attempt would fail noisily on every
// sync instead of refusing cleanly once.
func TestResolveInfraGateways_PlanesDisabledRefusesWithoutResolving(t *testing.T) {
	t.Parallel()

	// perGatewayStatusFixtures WITHOUT the token Secret: a resolve attempt
	// would mark the Gateway broken-transient rather than refused, so the
	// assertion below also proves no resolve happened.
	fixtures := perGatewayStatusFixtures(t)
	objs := fixtures[:0:0]

	for _, obj := range fixtures {
		if obj.GetName() == "pg-token" {
			continue
		}

		objs = append(objs, obj)
	}

	fakeClient := setupGatewayFakeClient(objs...)
	syncer := NewRouteSyncer(fakeClient, fakeClient.Scheme(), "cluster.local", "test-controller",
		config.NewResolver(fakeClient, "default", cfmetrics.NewNoopCollector(), verifiedClaims()),
		cfmetrics.NewNoopCollector(), nil)
	syncer.PerGatewayPlanesDisabled = true

	infra, err := syncer.resolveInfraGateways(context.Background())
	require.NoError(t, err)

	const key = "default/pg-gateway"

	assert.True(t, infra.isRefused(key), "an opted-in Gateway must be refused when planes are disabled")
	assert.Empty(t, infra.resolved, "no partition may exist for a refused Gateway")
	assert.False(t, infra.isTransient(key), "the refusal is deterministic, not a retryable blip")

	routeErr := gatewayPlaneError(key, infra)
	require.Error(t, routeErr, "a route bound to the refused Gateway must carry the refusal")
	assert.Contains(t, routeErr.Error(), "not programmed")
}

// TestApplyPlaneRefusals_PlanesDisabledSkipsArbitration pins that the
// disabled path never reaches tunnel-claim collection: collecting claims
// parses every opted-in Gateway's connector token, which reads Secrets the
// scoped cache cannot see. With everything already refused there is nothing
// to arbitrate.
func TestApplyPlaneRefusals_PlanesDisabledSkipsArbitration(t *testing.T) {
	t.Parallel()

	fixtures := perGatewayStatusFixtures(t)
	objs := fixtures[:0:0]

	for _, obj := range fixtures {
		if obj.GetName() == "pg-token" {
			continue
		}

		objs = append(objs, obj)
	}

	fakeClient := setupGatewayFakeClient(objs...)
	syncer := NewRouteSyncer(fakeClient, fakeClient.Scheme(), "cluster.local", "test-controller",
		config.NewResolver(fakeClient, "default", cfmetrics.NewNoopCollector(), verifiedClaims()),
		cfmetrics.NewNoopCollector(), nil)
	syncer.PerGatewayPlanesDisabled = true

	ctx := context.Background()

	infra, err := syncer.resolveInfraGateways(ctx)
	require.NoError(t, err)

	// Must not panic or read the (absent) token Secret; the refused set must
	// survive untouched.
	syncer.applyPlaneRefusals(ctx, infra, &config.ResolvedConfig{})

	assert.True(t, infra.isRefused("default/pg-gateway"))
	assert.Empty(t, infra.resolved)
}
