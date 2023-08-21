package tls

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"time"
)

func privateKeyToPem(rsaKey *rsa.PrivateKey) []byte {
	privateKey := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
	}
	return pem.EncodeToMemory(privateKey)
}

func certificateToPem(certs ...*x509.Certificate) []byte {
	var raw []byte
	for _, cert := range certs {
		certificate := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		raw = append(raw, pem.EncodeToMemory(certificate)...)
	}
	return raw
}

func pemToPrivateKey(raw []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(raw)
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func pemToCertificates(raw []byte) []*x509.Certificate {
	var certs []*x509.Certificate
	for {
		certPemBlock, next := pem.Decode(raw)
		if certPemBlock == nil {
			return certs
		}
		raw = next
		cert, err := x509.ParseCertificate(certPemBlock.Bytes)
		if err == nil {
			certs = append(certs, cert)
		} else {
			logger.Error(err, "failed to parse cert")
		}
	}
}

func removeExpiredCertificates(now time.Time, certs ...*x509.Certificate) []*x509.Certificate {
	var result []*x509.Certificate
	for _, cert := range certs {
		if !now.After(cert.NotAfter) {
			result = append(result, cert)
		}
	}
	return result
}

func allCertificatesExpired(now time.Time, certs ...*x509.Certificate) bool {
	for _, cert := range certs {
		if !now.After(cert.NotAfter) {
			return false
		}
	}
	return true
}

func validateCert(now time.Time, cert *x509.Certificate, caCerts ...*x509.Certificate) bool {
	pool := x509.NewCertPool()
	for _, cert := range caCerts {
		pool.AddCert(cert)
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: now}); err != nil {
		return false
	}
	return true
}

// inClusterServiceName The generated service name should be the common name for TLS certificate
func inClusterServiceName(config *Config) string {
	return config.ServiceName + "." + config.Namespace + ".svc"
}

func inClusterSvcName(config *Config) string {
	return "svc." + config.ServiceName
}

func GenerateTLSPairSecretName(config *Config) string {
	return inClusterServiceName(config) + ".tls-pair"
}

func GenerateRootCASecretName(config *Config) string {
	return inClusterServiceName(config) + ".tls-ca"
}
