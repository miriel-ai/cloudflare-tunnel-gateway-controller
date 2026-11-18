package controller

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/lexfrei/cloudflare-tunnel-gateway-controller/internal/render"
)

// TestLeftoverDedicatedPlanes pins the startup detection MIR-1607 runs when
// per-Gateway data planes are disabled: a previously-rendered dedicated proxy
// Deployment (Gateway-controlled, carrying the render label) cannot be torn
// down — the infra reconciler is off and the write RBAC is withdrawn — so it
// keeps serving its last-pushed routes while its Gateway reports
// Accepted=False. The operator must hear about each one; this is what finds
// them. Only Gateway-controlled Deployments count: the render label alone can
// be forged by anyone who can label a Deployment.
func TestLeftoverDedicatedPlanes(t *testing.T) {
	t.Parallel()

	scheme := runtime.NewScheme()
	require.NoError(t, appsv1.AddToScheme(scheme))

	controllerTrue := true

	leftover := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
		Name:      "cf-proxy-edge",
		Namespace: "tenant-a",
		Labels:    map[string]string{render.GatewayLabel: "edge"},
		OwnerReferences: []metav1.OwnerReference{{
			APIVersion: "gateway.networking.k8s.io/v1",
			Kind:       "Gateway",
			Name:       "edge",
			UID:        "uid-1",
			Controller: &controllerTrue,
		}},
	}}

	// Label without the Gateway owner: not a rendered plane, not reported.
	impostor := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
		Name:      "labelled-by-hand",
		Namespace: "tenant-b",
		Labels:    map[string]string{render.GatewayLabel: "whatever"},
	}}

	// No render label at all: ordinary workload, never listed.
	bystander := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
		Name:      "shop",
		Namespace: "tenant-c",
	}}

	cli := fake.NewClientBuilder().WithScheme(scheme).WithObjects(leftover, impostor, bystander).Build()

	found, err := leftoverDedicatedPlanes(context.Background(), cli)
	require.NoError(t, err)
	assert.Equal(t, []string{"tenant-a/cf-proxy-edge (Gateway edge)"}, found)
}
