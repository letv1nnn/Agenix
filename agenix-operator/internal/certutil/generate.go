package certutil

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/Bobbins228/Agenix/agenix-operator/internal/ca"
)

type CertificateBundle struct {
	CertPEM      []byte
	KeyPEM       []byte
	CaCertPEM    []byte
	SerialNumber string
	NotBefore    time.Time
	NotAfter     time.Time
	Fingerprint  string
	SPIFFEID     string
}

func (cb *CertificateBundle) ValidCertificateBundle() bool {
	if cb == nil {
		return false
	}
	if cb.CertPEM == nil || cb.KeyPEM == nil || cb.CaCertPEM == nil {
		return false
	}
	if cb.SerialNumber == "" {
		return false
	}
	if cb.NotBefore.IsZero() || cb.NotAfter.IsZero() {
		return false
	}
	if !cb.NotAfter.After(cb.NotBefore) {
		return false
	}
	if !strings.HasPrefix(cb.Fingerprint, "sha256:") || len(cb.Fingerprint) != 71 {
		return false
	}
	if _, _, _, err := ParseSPIFFEID(cb.SPIFFEID); err != nil {
		return false
	}
	return true
}

func GenerateAgentCertificate(authority *ca.CA, spiffeID string, ttl time.Duration) (*CertificateBundle, error) {
	certPEM, keyPEM, err := authority.IssueCertificate(spiffeID, ttl)
	if err != nil {
		return nil, fmt.Errorf("failed to issue certificate: %w", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	fingerprint, err := ComputeFingerprint(certPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to compute fingerprint: %w", err)
	}

	return &CertificateBundle{
		CertPEM:      certPEM,
		KeyPEM:       keyPEM,
		CaCertPEM:    authority.CertificatePem,
		SerialNumber: cert.SerialNumber.Text(16),
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		Fingerprint:  fingerprint,
		SPIFFEID:     spiffeID,
	}, nil
}

func ComputeFingerprint(certPEM []byte) (string, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", fmt.Errorf("failed to decode certificate PEM")
	}

	hash := sha256.Sum256(block.Bytes)
	return "sha256:" + hex.EncodeToString(hash[:]), nil
}
