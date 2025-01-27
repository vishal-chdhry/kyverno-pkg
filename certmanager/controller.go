package certmanager

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	"github.com/kyverno/pkg/tls"
	corev1 "k8s.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

const (
	ControllerName = "certmanager-controller"
	maxRetries     = 10
)

type CertController struct {
	Renewer       tls.CertRenewer
	caSecretName  string
	tlsSecretName string
	namespace     string
}

func NewController(
	certRenewer tls.CertRenewer,
	caSecretName string,
	tlsSecretName string,
	namespace string,
) *CertController {
	return &CertController{
		Renewer:       certRenewer,
		caSecretName:  caSecretName,
		tlsSecretName: tlsSecretName,
		namespace:     namespace,
	}
}

func (r *CertController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	if req.Namespace != r.namespace {
		return ctrl.Result{}, nil
	}

	if req.Name != r.caSecretName && req.Name != r.tlsSecretName {
		return ctrl.Result{}, nil
	}

	logger.V(4).Info("reconciling certificate")
	if err := r.renewCertificates(ctx); err != nil {
		logger.Error(err, "failed to renew certificates")
		return ctrl.Result{}, err
	}

	return ctrl.Result{
		RequeueAfter: tls.CertRenewalInterval,
	}, nil
}

func (r *CertController) renewCertificates(ctx context.Context) error {
	logger := log.FromContext(ctx)
	if err := RetryFunc(ctx, time.Second, 5*time.Second, logger, "failed to renew CA", r.Renewer.RenewCA)(); err != nil {
		return err
	}
	if err := RetryFunc(ctx, time.Second, 5*time.Second, logger, "failed to renew TLS", r.Renewer.RenewTLS)(); err != nil {
		return err
	}
	return nil
}

func (r *CertController) SetupWithManager(mgr ctrl.Manager) error {
	secretPredicate := predicate.NewPredicateFuncs(func(obj client.Object) bool {
		return obj.GetNamespace() == r.namespace && (obj.GetName() == r.caSecretName || obj.GetName() == r.tlsSecretName)
	})

	if err := ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Secret{}).
		WithEventFilter(secretPredicate).
		Complete(r); err != nil {
		return fmt.Errorf("failed to build controller: %w", err)
	}

	r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: client.ObjectKey{
			Namespace: r.namespace,
			Name:      r.caSecretName,
		},
	})

	return nil
}

func RetryFunc(ctx context.Context, retryInterval, timeout time.Duration, logger logr.Logger, msg string, run func(context.Context) error) func() error {
	return func() error {
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		registerTicker := time.NewTicker(retryInterval)
		defer registerTicker.Stop()
		var err error
		for {
			select {
			case <-registerTicker.C:
				if err = run(ctx); err != nil {
					logger.V(3).Info(msg, "reason", err.Error())
				} else {
					return nil
				}
			case <-ctx.Done():
				return fmt.Errorf("retry times out: %w", err)
			}
		}
	}
}
