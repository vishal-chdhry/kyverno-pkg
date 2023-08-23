package certmanager

import (
	"context"
	"time"

	"github.com/go-logr/logr"
	"github.com/vishal-chdhry/kyverno-pkg/tls"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	corev1informers "k8s.io/client-go/informers/core/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/util/workqueue"
)

const (
	// Workers is the number of workers for this controller
	Workers        = 1
	ControllerName = "certmanager-controller"
	maxRetries     = 10
)

type CertManagerController interface {
	// Run starts the controller
	Run(context.Context, int)
}

type controller struct {
	logger logr.Logger

	renewer tls.CertRenewer

	// listers
	caLister  corev1listers.SecretLister
	tlsLister corev1listers.SecretLister

	// queue
	queue      workqueue.RateLimitingInterface
	caEnqueue  EnqueueFunc
	tlsEnqueue EnqueueFunc

	tlsConfig *tls.Config
}

func NewController(
	logger logr.Logger,
	caInformer corev1informers.SecretInformer,
	tlsInformer corev1informers.SecretInformer,
	certRenewer tls.CertRenewer,
	config *tls.Config,
) CertManagerController {
	queue := workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), ControllerName)
	c := controller{
		logger:     logger,
		renewer:    certRenewer,
		caLister:   caInformer.Lister(),
		tlsLister:  tlsInformer.Lister(),
		queue:      queue,
		caEnqueue:  AddDefaultEventHandlers(logger, caInformer.Informer(), queue),
		tlsEnqueue: AddDefaultEventHandlers(logger, tlsInformer.Informer(), queue),
		tlsConfig:  config,
	}
	return &c
}

func (c *controller) Run(ctx context.Context, workers int) {
	// we need to enqueue our secrets in case they don't exist yet in the cluster
	// this way we ensure the reconcile happens (hence renewal/creation)
	if err := c.tlsEnqueue(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: c.tlsConfig.Namespace,
			Name:      tls.GenerateTLSPairSecretName(c.tlsConfig),
		},
	}); err != nil {
		c.logger.V(2).Error(err, "failed to enqueue secret", "name", tls.GenerateTLSPairSecretName(c.tlsConfig))
	}
	if err := c.caEnqueue(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: c.tlsConfig.Namespace,
			Name:      tls.GenerateRootCASecretName(c.tlsConfig),
		},
	}); err != nil {
		c.logger.V(2).Error(err, "failed to enqueue CA secret", "name", tls.GenerateRootCASecretName(c.tlsConfig))
	}
	run(ctx, c.logger, ControllerName, time.Second, c.queue, workers, maxRetries, c.reconcile, c.ticker)
}

func (c *controller) reconcile(ctx context.Context, logger logr.Logger, key, namespace, name string) error {
	if namespace != c.tlsConfig.Namespace {
		return nil
	}
	if name != tls.GenerateTLSPairSecretName(c.tlsConfig) && name != tls.GenerateRootCASecretName(c.tlsConfig) {
		return nil
	}
	return c.renewCertificates(ctx)
}

func (c *controller) ticker(ctx context.Context, logger logr.Logger) {
	certsRenewalTicker := time.NewTicker(tls.CertRenewalInterval)
	defer certsRenewalTicker.Stop()
	for {
		select {
		case <-certsRenewalTicker.C:
			{
				list, err := c.caLister.List(labels.Everything())
				if err == nil {
					for _, secret := range list {
						if err := c.caEnqueue(secret); err != nil {
							logger.V(2).Error(err, "failed to enqueue secret", "name", secret.Name)
						}
					}
				} else {
					logger.V(2).Error(err, "falied to list secrets")
				}
			}
			{
				list, err := c.tlsLister.List(labels.Everything())
				if err == nil {
					for _, secret := range list {
						if err := c.tlsEnqueue(secret); err != nil {
							logger.V(2).Error(err, "failed to enqueue secret", "name", secret.Name)
						}
					}
				} else {
					logger.V(2).Error(err, "falied to list secrets")
				}
			}
		case <-ctx.Done():
			return
		}
	}
}

func (c *controller) renewCertificates(ctx context.Context) error {
	if err := retryFunc(ctx, time.Second, 5*time.Second, c.logger, "failed to renew CA", c.renewer.RenewCA)(); err != nil {
		return err
	}
	if err := retryFunc(ctx, time.Second, 5*time.Second, c.logger, "failed to renew TLS", c.renewer.RenewTLS)(); err != nil {
		return err
	}
	return nil
}
