package tls

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	interfacev1 "k8s.io/client-go/kubernetes/typed/core/v1"
)

const (
	// CertRenewalInterval is the renewal interval for rootCA
	CertRenewalInterval = 12 * time.Hour
	// CAValidityDuration is the valid duration for CA certificates
	CAValidityDuration = 365 * 24 * time.Hour
	// TLSValidityDuration is the valid duration for TLS certificates
	TLSValidityDuration = 150 * 24 * time.Hour
	rootCAKey           = "rootCA.crt"
)

type CertValidator interface {
	// ValidateCert checks the certificates validity
	ValidateCert(context.Context) (bool, error)
}

type TLSCerts struct {
	Cert *x509.Certificate

	Key *rsa.PrivateKey
}

type CertRenewer interface {
	// RenewCA renews the CA certificate if needed
	RenewCA(context.Context) error
	// RenewTLS renews the TLS certificate if needed
	RenewTLS(context.Context) error
}

// certRenewer creates rootCA and pem pair to register
// webhook configurations and webhook server
// renews RootCA at the given interval
type certRenewer struct {
	logger              logr.Logger
	client              interfacev1.SecretInterface
	certRenewalInterval time.Duration
	caValidityDuration  time.Duration
	tlsValidityDuration time.Duration
	config              *Config

	server string
}

type Config struct {
	ServiceName string
	Namespace   string
}

// NewCertRenewer returns an instance of CertRenewer
func NewCertRenewer(
	log logr.Logger,
	client interfacev1.SecretInterface,
	certRenewalInterval,
	caValidityDuration,
	tlsValidityDuration time.Duration,
	server string,
	config *Config,
	informer *chan TLSCerts,
) *certRenewer {
	logger = log
	return &certRenewer{
		logger:              log,
		client:              client,
		certRenewalInterval: certRenewalInterval,
		caValidityDuration:  caValidityDuration,
		tlsValidityDuration: tlsValidityDuration,
		server:              server,
		config:              config,
	}
}

// RenewCA renews the CA certificate if needed
func (c *certRenewer) RenewCA(ctx context.Context) error {
	secret, key, certs, err := c.decodeCASecret(ctx)
	if err != nil && !apierrors.IsNotFound(err) {
		c.logger.V(2).Error(err, "failed to read CA")
		return err
	}
	now := time.Now()
	certs = removeExpiredCertificates(now, certs...)
	if !allCertificatesExpired(now.Add(5*c.certRenewalInterval), certs...) {
		c.logger.V(2).Info("CA certificate does not need to be renewed")
		return nil
	}

	if secret != nil && secret.Type != corev1.SecretTypeTLS {
		c.logger.V(2).Info("CA secret type is not TLS, we're going to delete it and regenrate one")
		err := c.client.Delete(ctx, secret.Name, metav1.DeleteOptions{})
		if err != nil {
			c.logger.V(2).Error(err, "failed to delete CA secret")
		}
		return err
	}
	caKey, caCert, err := generateCA(key, c.caValidityDuration)
	if err != nil {
		c.logger.V(2).Error(err, "failed to generate CA")
		return err
	}
	certs = append(certs, caCert)
	if err := c.writeCASecret(ctx, caKey, certs...); err != nil {
		c.logger.V(2).Error(err, "failed to write CA")
		return err
	}
	c.logger.V(2).Info("CA was renewed")
	return nil
}

// RenewTLS renews the TLS certificate if needed
func (c *certRenewer) RenewTLS(ctx context.Context) error {
	_, caKey, caCerts, err := c.decodeCASecret(ctx)
	if err != nil {
		c.logger.V(2).Error(err, "failed to read CA")
		return err
	}
	secret, _, cert, err := c.decodeTLSSecret(ctx)
	if err != nil && !apierrors.IsNotFound(err) {
		c.logger.V(2).Error(err, "failed to read TLS")
		return err
	}
	now := time.Now()
	if cert != nil && !allCertificatesExpired(now.Add(5*c.certRenewalInterval), cert) {
		c.logger.V(2).Info("TLS certificate does not need to be renewed")
		return nil
	}

	if secret != nil && secret.Type != corev1.SecretTypeTLS {
		c.logger.V(2).Info("TLS secret type is not TLS, we're going to delete it and regenrate one")
		err := c.client.Delete(ctx, secret.Name, metav1.DeleteOptions{})
		if err != nil {
			c.logger.V(2).Error(err, "failed to delete TLS secret")
		}
		return err
	}
	tlsKey, tlsCert, err := generateTLS(c.server, caCerts[len(caCerts)-1], caKey, c.tlsValidityDuration, c.config)
	if err != nil {
		c.logger.V(2).Error(err, "failed to generate TLS")
		return err
	}
	if err := c.writeTLSSecret(ctx, tlsKey, tlsCert); err != nil {
		c.logger.V(2).Error(err, "failed to write TLS")
		return err
	}
	c.logger.V(2).Info("TLS was renewed")
	return nil
}

// ValidateCert validates the CA Cert
func (c *certRenewer) ValidateCert(ctx context.Context) (bool, error) {
	_, _, caCerts, err := c.decodeCASecret(ctx)
	if err != nil {
		return false, err
	}
	_, _, cert, err := c.decodeTLSSecret(ctx)
	if err != nil {
		return false, err
	}
	return validateCert(time.Now(), cert, caCerts...), nil
}

func (c *certRenewer) getSecret(ctx context.Context, name string) (*corev1.Secret, error) {
	if s, err := c.client.Get(ctx, name, metav1.GetOptions{}); err != nil {
		return nil, err
	} else {
		return s, nil
	}
}

func (c *certRenewer) decodeSecret(ctx context.Context, name string) (*corev1.Secret, *rsa.PrivateKey, []*x509.Certificate, error) {
	secret, err := c.getSecret(ctx, name)
	if err != nil {
		return nil, nil, nil, err
	}
	var certBytes, keyBytes []byte
	if secret != nil {
		keyBytes = secret.Data[corev1.TLSPrivateKeyKey]
		certBytes = secret.Data[corev1.TLSCertKey]
		if len(certBytes) == 0 {
			certBytes = secret.Data[rootCAKey]
		}
	}
	var key *rsa.PrivateKey
	if keyBytes != nil {
		usedkey, err := pemToPrivateKey(keyBytes)
		if err != nil {
			return nil, nil, nil, err
		}
		key = usedkey
	}
	return secret, key, pemToCertificates(certBytes), nil
}

func (c *certRenewer) decodeCASecret(ctx context.Context) (*corev1.Secret, *rsa.PrivateKey, []*x509.Certificate, error) {
	return c.decodeSecret(ctx, GenerateRootCASecretName(c.config))
}

func (c *certRenewer) decodeTLSSecret(ctx context.Context) (*corev1.Secret, *rsa.PrivateKey, *x509.Certificate, error) {
	secret, key, certs, err := c.decodeSecret(ctx, GenerateTLSPairSecretName(c.config))
	if err != nil {
		return nil, nil, nil, err
	}
	if len(certs) == 0 {
		return secret, key, nil, nil
	} else if len(certs) == 1 {
		return secret, key, certs[0], nil
	} else {
		return nil, nil, nil, err
	}
}

func (c *certRenewer) writeSecret(ctx context.Context, name string, key *rsa.PrivateKey, certs ...*x509.Certificate) error {
	logger := c.logger.V(2).WithValues("name", name, "namespace", c.config.Namespace)
	secret, err := c.getSecret(ctx, name)
	if err != nil && !apierrors.IsNotFound(err) {
		logger.V(2).Error(err, "failed to get CA secret")
		return err
	}
	if secret == nil {
		secret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: c.config.Namespace,
			},
			Type: corev1.SecretTypeTLS,
		}
	}
	secret.Type = corev1.SecretTypeTLS
	secret.Data = map[string][]byte{
		corev1.TLSCertKey:       certificateToPem(certs...),
		corev1.TLSPrivateKeyKey: privateKeyToPem(key),
	}
	if secret.ResourceVersion == "" {
		if _, err := c.client.Create(ctx, secret, metav1.CreateOptions{}); err != nil {
			logger.V(2).Error(err, "failed to update secret")
			return err
		} else {
			c.logger.V(2).Info("secret created")
		}
	} else {
		if _, err := c.client.Update(ctx, secret, metav1.UpdateOptions{}); err != nil {
			logger.V(2).Error(err, "failed to update secret")
			return err
		} else {
			logger.V(2).Info("secret updated")
		}
	}
	return nil
}

// writeCASecret stores the CA cert in secret
func (c *certRenewer) writeCASecret(ctx context.Context, key *rsa.PrivateKey, certs ...*x509.Certificate) error {
	return c.writeSecret(ctx, GenerateRootCASecretName(c.config), key, certs...)
}

// writeTLSSecret Writes the pair of TLS certificate and key to the specified secret.
func (c *certRenewer) writeTLSSecret(ctx context.Context, key *rsa.PrivateKey, cert *x509.Certificate) error {
	return c.writeSecret(ctx, GenerateTLSPairSecretName(c.config), key, cert)
}
