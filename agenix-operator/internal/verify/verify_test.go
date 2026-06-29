package verify

import (
	"testing"
	"time"

	"github.com/Bobbins228/Agenix/agenix-operator/internal/ca"
)

const testSpiffeID = "spiffe://example.test/ns/default/sa/my-agent"
const ttl = 24 * time.Hour

func TestVerifyCertificateChain_Valid(t *testing.T) {
	// issue a cert w CA
	auth, err := ca.NewCA()
	if err != nil {
		t.Fatalf("NewCA returned an error: %v", err)
	}

	// issue certificate
	certPEM, _, err := auth.IssueCertificate(testSpiffeID, ttl)
	if err != nil {
		t.Fatalf("IssueCertificate returned an error: %v", err)
	}

	// verify it passes chain validation
	if err := VerifyCertificateChain(certPEM, auth.CertificatePem); err != nil {
		t.Fatalf("VerifyCertificateChain returned an error: %v", err)
	}
}

func TestVerifyCertificateChain_WrongCA(t *testing.T) {
	// create 2 CAS
	ca1, err := ca.NewCA()
	if err != nil {
		t.Fatalf("NewCA returned an error: %v", err)
	}
	ca2, err := ca.NewCA()
	if err != nil {
		t.Fatalf("NewCA returned an error: %v", err)
	}
	// issue cert w CA1
	certPEM, _, err := ca1.IssueCertificate(testSpiffeID, ttl)
	if err != nil {
		t.Fatalf("IssueCertificate returned an error: %v", err)
	}
	// verify against CA2
	err = VerifyCertificateChain(certPEM, ca2.CertificatePem)
	if err == nil {
		t.Fatalf("expected VerifyCertificateChain to fail: wrong CA")
	}
}

func TestExtractSPIFFEID(t *testing.T) {
	// issue cert w known SPIFFE ID
	auth, err := ca.NewCA()
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}

	certPEM, _, err := auth.IssueCertificate(testSpiffeID, ttl)
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}

	// extract spiffe ID
	extracted, err := ExtractSPIFFEID(certPEM)
	if err != nil {
		t.Fatalf("ExtractSPIFFEID: %v", err)
	}

	// check matches expected spiffe ID
	if extracted != testSpiffeID {
		t.Fatalf("got SPIFFE ID %q, want %q", extracted, testSpiffeID)
	}
}

func TestValidateIdentity_Mismatch(t *testing.T) {
	// issue cert with spiffe id
	auth, err := ca.NewCA()
	if err != nil {
		t.Fatalf("NewCA returned an error: %v", err)
	}

	certPEM, _, err := auth.IssueCertificate(testSpiffeID, ttl)
	if err != nil {
		t.Fatalf("IssueCertificate returned an error: %v", err)
	}

	// validate against spiffe id B
	result, err := ValidateIdentity(certPEM, auth.CertificatePem, "spiffe://example.test/ns/default/sa/other-agent")
	if err != nil {
		t.Fatalf("ValidateIdentity returned an error: %v", err)
	}
	if result.SPIFFEIDMatch {
		t.Fatal("expected SPIFFEIDMatch = false")
	}
	if !result.ChainValid {
		t.Fatal("expected chain to be valid")
	}
	// should report mismatch
}

func TestValidateIdentity_Expired(t *testing.T) {
	// issue cert w 1 nanosecond ttl
	auth, err := ca.NewCA()
	if err != nil {
		t.Fatalf("NewCA returned an error: %v", err)
	}

	certPEM, _, err := auth.IssueCertificate(testSpiffeID, 1*time.Nanosecond)
	if err != nil {
		t.Fatalf("IssueCertificate returned an error: %v", err)
	}

	// wait
	time.Sleep(5 * time.Millisecond)

	result, err := ValidateIdentity(certPEM, auth.CertificatePem, testSpiffeID)
	if err != nil {
		t.Fatalf("ValidateIdentity returned an error: %v", err)
	}
	if !result.IsExpired { // should be expired (1 nanosecond)
		t.Fatal("expected IsExpired = true")
	}
	if !result.ChainValid {
		t.Fatal("expected chain to be valid")
	}
	if !result.SPIFFEIDMatch {
		t.Fatal("expected SPIFFE ID to match")
	}
}
