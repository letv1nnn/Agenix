package certutil

import (
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/Bobbins228/Agenix/agenix-operator/internal/ca"
)

const testSPIFFEID = "spiffe://example.org/ns/default/sa/test-agent"

func TestGenerateAgentCertificate(t *testing.T) {
	authority, err := ca.NewCA()
	if err != nil {
		t.Fatalf("failed to create CA: %v", err)
	}

	bundle, err := GenerateAgentCertificate(authority, testSPIFFEID, 24*time.Hour)
	if err != nil {
		t.Fatalf("failed to generate agent certificate: %v", err)
	}
	if bundle == nil {
		t.Fatal("generated certificate bundle is nil")
	}

	if !bundle.ValidCertificateBundle() {
		t.Error("bundle failed validation")
	}

	if bundle.SPIFFEID != testSPIFFEID {
		t.Errorf("SPIFFEID: got %q, want %q", bundle.SPIFFEID, testSPIFFEID)
	}

	// verify cert is signed by CA
	block, _ := pem.Decode(bundle.CertPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse cert: %v", err)
	}

	if err := cert.CheckSignatureFrom(authority.Certificate); err != nil {
		t.Errorf("cert not signed by CA: %v", err)
	}
}

func TestGenerateAgentCertificate_SPIFFEIDInSAN(t *testing.T) {
	authority, err := ca.NewCA()
	if err != nil {
		t.Fatalf("failed to create CA: %v", err)
	}

	bundle, err := GenerateAgentCertificate(authority, testSPIFFEID, 24*time.Hour)
	if err != nil {
		t.Fatalf("failed to generate certificate: %v", err)
	}

	block, _ := pem.Decode(bundle.CertPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse cert: %v", err)
	}

	if len(cert.URIs) == 0 {
		t.Fatal("no URI SANs in certificate")
	}
	if cert.URIs[0].String() != testSPIFFEID {
		t.Errorf("SAN URI: got %q, want %q", cert.URIs[0].String(), testSPIFFEID)
	}
}

func TestComputeFingerprint(t *testing.T) {
	authority, err := ca.NewCA()
	if err != nil {
		t.Fatalf("failed to create CA: %v", err)
	}

	bundle, err := GenerateAgentCertificate(authority, testSPIFFEID, 24*time.Hour)
	if err != nil {
		t.Fatalf("failed to generate certificate: %v", err)
	}

	fp, err := ComputeFingerprint(bundle.CertPEM)
	if err != nil {
		t.Fatalf("failed to compute fingerprint: %v", err)
	}

	if !strings.HasPrefix(fp, "sha256:") {
		t.Errorf("fingerprint missing sha256: prefix: %q", fp)
	}

	// sha256 = 32 bytes = 64 hex chars + "sha256:" prefix = 71 total
	if len(fp) != 71 {
		t.Errorf("fingerprint wrong length: got %d, want 71", len(fp))
	}
}

func TestGenerateAgentCertificate_TTL(t *testing.T) {
	authority, err := ca.NewCA()
	if err != nil {
		t.Fatalf("failed to create CA: %v", err)
	}

	ttl := 1 * time.Hour
	bundle, err := GenerateAgentCertificate(authority, testSPIFFEID, ttl)
	if err != nil {
		t.Fatalf("failed to generate certificate: %v", err)
	}

	expectedExpiry := bundle.NotBefore.Add(ttl)
	diff := bundle.NotAfter.Sub(expectedExpiry)
	if diff < -time.Second || diff > time.Second {
		t.Errorf("NotAfter off by %v: got %v, want ~%v", diff, bundle.NotAfter, expectedExpiry)
	}
}
