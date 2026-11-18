package controller

import (
	"context"
	"sort"

	"github.com/cockroachdb/errors"
	appsv1 "k8s.io/api/apps/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/lexfrei/cloudflare-tunnel-gateway-controller/internal/render"
)

// addLeftoverPlaneWarning registers a one-shot startup check for an
// installation that disabled per-Gateway data planes (MIR-1607): a dedicated
// proxy Deployment rendered BEFORE the switch cannot be torn down now — the
// infra reconciler is off and the write RBAC is withdrawn — and its tunnel
// connector keeps serving the plane's last-pushed routes while the owning
// Gateway reports Accepted=False/PerGatewayDataPlanesDisabled. That standing
// contradiction is the operator's to resolve (delete the opted-in Gateways,
// or re-enable the feature and opt them out first), so every leftover is
// reported as an Error log at startup, where turning the toggle off is the
// action that gets reviewed.
//
// Detection is read-only (deployments get/list/watch stays cluster-wide) and
// counts only Gateway-controlled Deployments: the render label alone can be
// put on anything by anyone able to label a Deployment.
func addLeftoverPlaneWarning(mgr ctrl.Manager) error {
	err := mgr.Add(manager.RunnableFunc(func(ctx context.Context) error {
		logger := log.FromContext(ctx).WithName("leftover-planes")

		leftovers, listErr := leftoverDedicatedPlanes(ctx, mgr.GetClient())
		if listErr != nil {
			// Reported, not fatal: failing the whole manager over a warning
			// scan would take the shared plane down with it.
			logger.Error(listErr, "could not check for leftover dedicated data planes")

			return nil
		}

		for _, plane := range leftovers {
			logger.Error(nil, "per-Gateway data planes are disabled but a previously rendered plane still exists; "+
				"it keeps serving its LAST-PUSHED routes and this controller holds no RBAC to remove it — "+
				"delete the opted-in Gateway, or re-enable perGatewayDataPlanes and opt it out first",
				"deployment", plane)
		}

		return nil
	}))

	return errors.Wrap(err, "failed to add leftover-plane warning")
}

// leftoverDedicatedPlanes lists the Gateway-controlled proxy Deployments a
// per-Gateway render left behind, as "namespace/name (Gateway <owner>)".
func leftoverDedicatedPlanes(ctx context.Context, cli client.Client) ([]string, error) {
	var deployments appsv1.DeploymentList
	if err := cli.List(ctx, &deployments, client.HasLabels{render.GatewayLabel}); err != nil {
		return nil, errors.Wrap(err, "listing rendered proxy Deployments")
	}

	var leftovers []string

	for i := range deployments.Items {
		dep := &deployments.Items[i]
		if !controlledByGateway(dep) {
			continue
		}

		owner := metav1GetControllerName(dep)
		leftovers = append(leftovers, dep.Namespace+"/"+dep.Name+" (Gateway "+owner+")")
	}

	sort.Strings(leftovers)

	return leftovers, nil
}

// metav1GetControllerName names a Deployment's controlling owner; callers
// check controlledByGateway first, so the owner exists.
func metav1GetControllerName(dep *appsv1.Deployment) string {
	for i := range dep.OwnerReferences {
		ref := &dep.OwnerReferences[i]
		if ref.Controller != nil && *ref.Controller {
			return ref.Name
		}
	}

	return "unknown"
}
