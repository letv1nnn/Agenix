package verify

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/Bobbins228/Agenix/agenix-operator/internal/certutil"
)

func parseCertPEM(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate")
	}
	return cert, nil
}

func VerifyCertificateChain(certPEM, caCertPEM []byte) error {
	// parse leaf cert from PEM
	leafCert, err := parseCertPEM(certPEM)
	if err != nil {
		return err
	}

	// parse ca certificate from pem
	parsedCaCert, err := parseCertPEM(caCertPEM)
	if err != nil {
		return err
	}

	caPool := x509.NewCertPool()
	caPool.AddCert(parsedCaCert)

	_, err = leafCert.Verify(x509.VerifyOptions{Roots: caPool})
	if err != nil {
		return err
	}
	return nil
}

func ExtractSPIFFEID(certPEM []byte) (string, error) {
	// parse cert from PEM
	leafCert, err := parseCertPEM(certPEM)
	if err != nil {
		return "", err
	}
	// extract URI SAN
	if len(leafCert.URIs) != 1 {
		return "", fmt.Errorf("expected 1 cert URI, found %v", len(leafCert.URIs))
	}

	uri := leafCert.URIs[0]
	if uri.Scheme != "spiffe" {
		return "", fmt.Errorf("URI SAN is not SPIFFE, got %v", uri.Scheme)
	}

	spiffeID := uri.String()

	// extra check: use certutil.ParseSPIFFEID to validate format
	if _, _, _, err := certutil.ParseSPIFFEID(spiffeID); err != nil {
		return "", fmt.Errorf("invalid SPIFFE ID %q: %v", spiffeID, err)
	}

	// return SPIFFE ID string
	return spiffeID, nil
}

type VerificationResult struct {
	ChainValid    bool
	SPIFFEIDMatch bool
	ExpiresAt     time.Time
	IsExpired     bool
}

func ValidateIdentity(certPEM, caCertPEM []byte, expectedSPIFFEID string) (*VerificationResult, error) {
	result := &VerificationResult{}

	// parse leaf cert from pem
	leafCert, err := parseCertPEM(certPEM)
	if err != nil {
		return nil, err
	}
	result.ExpiresAt = leafCert.NotAfter
	result.IsExpired = time.Now().After(leafCert.NotAfter)

	// parse ca certificate from pem
	parsedCaCert, err := parseCertPEM(caCertPEM)
	if err != nil {
		return nil, err
	}

	// create x509.CertPool with CA cert
	caPool := x509.NewCertPool()
	caPool.AddCert(parsedCaCert)

	verifyTime := leafCert.NotBefore.Add(time.Second)
	if verifyTime.After(leafCert.NotAfter) {
		verifyTime = leafCert.NotBefore
	}

	_, err = leafCert.Verify(x509.VerifyOptions{
		Roots:       caPool,
		CurrentTime: verifyTime,
	})
	if err != nil {
		result.ChainValid = false
		return result, fmt.Errorf("failed to verify certificate chain: %w", err)
	}
	result.ChainValid = true
	// instead of calling VerifyCertificateChain, it now uses a modified version of the code to account for the expiry time

	// calls ExtractSPIFFEID and compares with expected ID
	extractedID, err := ExtractSPIFFEID(certPEM)
	if err != nil {
		result.SPIFFEIDMatch = false
		return result, err
	}

	result.SPIFFEIDMatch = (extractedID == expectedSPIFFEID)

	// returns a VerificationResult struct with ChainValid bool, SPIFFEIDMatch bool, ExpiresAt time.Time, IsExpired bool
	return result, nil
}
