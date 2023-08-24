package certmanager

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"time"

	"github.com/go-logr/logr"
	tlsMgr "github.com/kyverno/pkg/tls"
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

	// GetCertificate can be used to fetch secrets in tls.Config
	GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error)
}

type controller struct {
	logger logr.Logger

	renewer tlsMgr.CertRenewer

	// listers
	caLister  corev1listers.SecretLister
	tlsLister corev1listers.SecretLister

	// queue
	queue      workqueue.RateLimitingInterface
	caEnqueue  EnqueueFunc
	tlsEnqueue EnqueueFunc

	tlsConfig *tlsMgr.Config
}

func NewController(
	logger logr.Logger,
	caInformer corev1informers.SecretInformer,
	tlsInformer corev1informers.SecretInformer,
	certRenewer tlsMgr.CertRenewer,
	config *tlsMgr.Config,
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
			Name:      tlsMgr.GenerateTLSPairSecretName(c.tlsConfig),
		},
	}); err != nil {
		c.logger.V(2).Error(err, "failed to enqueue secret", "name", tlsMgr.GenerateTLSPairSecretName(c.tlsConfig))
	}
	if err := c.caEnqueue(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: c.tlsConfig.Namespace,
			Name:      tlsMgr.GenerateRootCASecretName(c.tlsConfig),
		},
	}); err != nil {
		c.logger.V(2).Error(err, "failed to enqueue CA secret", "name", tlsMgr.GenerateRootCASecretName(c.tlsConfig))
	}
	run(ctx, c.logger, ControllerName, time.Second, c.queue, workers, maxRetries, c.reconcile, c.ticker)
}

func (c *controller) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	secret, err := c.tlsLister.Secrets(c.tlsConfig.Namespace).Get(tlsMgr.GenerateTLSPairSecretName(c.tlsConfig))
	if err != nil {
		return nil, err
	} else if secret == nil {
		return nil, errors.New("tls secret not found")
	} else if secret.Type != corev1.SecretTypeTLS {
		return nil, errors.New("secret is not a TLS secret")
	}

	tlscert, err := base64.StdEncoding.DecodeString(string(secret.Data[corev1.TLSCertKey]))
	if err != nil {
		return nil, err
	}

	tlskey, err := base64.StdEncoding.DecodeString(string(secret.Data[corev1.TLSPrivateKeyKey]))
	if err != nil {
		return nil, err
	}

	cert, err := tls.X509KeyPair(tlscert, tlskey)
	if err != nil {
		return nil, err
	}

	return &cert, nil
}

func (c *controller) reconcile(ctx context.Context, logger logr.Logger, key, namespace, name string) error {
	if namespace != c.tlsConfig.Namespace {
		return nil
	}
	if name != tlsMgr.GenerateTLSPairSecretName(c.tlsConfig) && name != tlsMgr.GenerateRootCASecretName(c.tlsConfig) {
		return nil
	}
	return c.renewCertificates(ctx)
}

func (c *controller) ticker(ctx context.Context, logger logr.Logger) {
	certsRenewalTicker := time.NewTicker(tlsMgr.CertRenewalInterval)
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
