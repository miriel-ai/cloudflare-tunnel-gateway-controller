package controller

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// cacheScopeErrorMarker is the fixed fragment of the error
// controller-runtime's multiNamespaceCache returns for a cached read outside
// its namespace set (multi_namespace_cache.go, "unable to get/list: …
// because of unknown namespace for the cache"). It is a plain fmt.Errorf, so
// text is the only handle callers have on it.
const cacheScopeErrorMarker = "because of unknown namespace for the cache"

// secretsResource names the resource in the converted error and its details.
const secretsResource = "secrets"

// causeOutOfScopeNamespace marks the NotFound scopeNotFound converts an
// out-of-scope read into, so consumers can tell "outside the controller's
// scoped Secret cache" apart from a Secret that is genuinely absent and
// surface the remedy instead of a plain "not found" (MIR-1676).
const causeOutOfScopeNamespace metav1.CauseType = "OutOfScopeNamespace"

// newSecretScopeClient is the manager's client constructor when the Secret
// cache is scoped to an explicit namespace list (MIR-1607). It wraps the
// default client so an out-of-scope cached read surfaces as a deterministic
// NotFound instead of the cache's plain error: every Secret consumer in this
// controller classifies NotFound as a verdict on the reference (listener
// ResolvedRefs=False, InvalidParameters, a refused client-cert ref) and
// anything else as transient — and a transient error on one Gateway's Secret
// would stall its whole partition's config push and requeue forever, while
// nothing an operator does short of listing the namespace can ever heal it.
// Within this installation's visibility the Secret genuinely does not exist;
// the message carries the difference, and the remedy.
//
//nolint:gocritic // hugeParam: the signature is controller-runtime's client.NewClientFunc, not ours to change
func newSecretScopeClient(config *rest.Config, options client.Options) (client.Client, error) {
	inner, err := client.New(config, options)
	if err != nil {
		return nil, err //nolint:wrapcheck // the manager reports its client constructor's error as-is
	}

	return &secretScopeClient{Client: inner}, nil
}

// secretScopeClient converts the scoped cache's out-of-scope read error into
// a NotFound (see newSecretScopeClient). Only the Secret cache is namespace-
// scoped, so only Secret reads can produce the marker.
type secretScopeClient struct {
	client.Client
}

func (c *secretScopeClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	return scopeNotFound(c.Client.Get(ctx, key, obj, opts...), key.Namespace, key.Name)
}

func (c *secretScopeClient) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	listOpts := client.ListOptions{}
	listOpts.ApplyOptions(opts)

	return scopeNotFound(c.Client.List(ctx, list, opts...), listOpts.Namespace, "")
}

// scopeNotFound maps the cache's out-of-scope error onto a NotFound
// StatusError whose message names the namespace and the remedy; every other
// error (and nil) passes through untouched.
func scopeNotFound(err error, namespace, name string) error {
	if err == nil || !strings.Contains(err.Error(), cacheScopeErrorMarker) {
		return err
	}

	return outOfScopeSecretError(namespace, name)
}

// outOfScopeSecretError builds the deterministic NotFound for a Secret read
// outside the scoped cache: the message names the namespace and the remedy,
// and the causeOutOfScopeNamespace cause makes it detectable for
// secretScopeMessage.
func outOfScopeSecretError(namespace, name string) *apierrors.StatusError {
	what := "its " + secretsResource
	if name != "" {
		what = fmt.Sprintf("secret %q", name)
	}

	// Word order matters: the namespace (bounded at 63 by Kubernetes) and the
	// remedy come before the variable-length Secret name (up to 253), so when
	// a consumer caps the message at maxConditionMessageLength the cut can
	// only ever eat the name — never the remedy.
	return &apierrors.StatusError{ErrStatus: metav1.Status{
		Status: metav1.StatusFailure,
		Code:   http.StatusNotFound,
		Reason: metav1.StatusReasonNotFound,
		Message: fmt.Sprintf(
			"namespace %q is outside the controller's scoped Secret cache (--secret-namespaces); "+
				"list it in perGatewayDataPlanes.extraSecretNamespaces to admit %s",
			namespace, what),
		Details: &metav1.StatusDetails{
			Kind:   secretsResource,
			Name:   name,
			Causes: []metav1.StatusCause{{Type: causeOutOfScopeNamespace}},
		},
	}}
}

// missingSecretMessage builds the operator-facing condition message for a
// NotFound certificate-Secret read: the scope diagnostic (with its remedy)
// when the scoped cache refused the read, plain not-found when the Secret is
// genuinely absent. Capped at maxConditionMessageLength; the scope
// diagnostic's word order guarantees a cut only ever eats the Secret name.
func missingSecretMessage(err error, namespace, name string) string {
	if scopeMsg, ok := secretScopeMessage(err); ok {
		return truncateMessage(scopeMsg)
	}

	return truncateMessage(fmt.Sprintf("Secret %s/%s not found", namespace, name))
}

// secretScopeMessage returns the scope diagnostic when err is (or wraps) the
// NotFound outOfScopeSecretError builds, and false for every other error —
// notably a plain NotFound for a Secret that is genuinely absent. Consumers
// use it to put the out-of-scope remedy on their operator-facing condition
// message instead of reporting the Secret as missing.
func secretScopeMessage(err error) (string, bool) {
	var statusErr *apierrors.StatusError
	if !errors.As(err, &statusErr) || statusErr.ErrStatus.Details == nil {
		return "", false
	}

	for _, cause := range statusErr.ErrStatus.Details.Causes {
		if cause.Type == causeOutOfScopeNamespace {
			return statusErr.ErrStatus.Message, true
		}
	}

	return "", false
}
