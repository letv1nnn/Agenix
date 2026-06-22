package ca

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

const testSpiffeID = "spiffe://example.test/ns/default/sa/my-agent"

func parseCertPEM(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("failed to decode certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}
	return cert
} // helper by Cursor

func TestNewCA(t *testing.T) {
	ca, err := NewCA()
	if err != nil {
		t.Fatalf("NewCA returned an error: %v", err)
	}

	if ca.PrivateKey == nil {
		t.Fatal("Private key is nil")
	}

	if ca.Certificate == nil {
		t.Fatal("Cert is nil")
	}

	if len(ca.CertificatePem) == 0 {
		t.Fatal("CertificatePem is empty")
	}

	// verify it uses ECDSA P-256,
	if ca.PrivateKey.Curve.Params().Name != elliptic.P256().Params().Name {
		t.Errorf("expected P-256 curve, got %s", ca.PrivateKey.Curve.Params().Name)
	}

	// verify IsCA = true
	if !ca.Certificate.IsCA {
		t.Error("expected IsCA=true")
	}

	// verify self signed
	if ca.Certificate.Issuer.String() != ca.Certificate.Subject.String() {
		t.Error("expected self signed cert")
	}
}

func TestIssueCertificate(t *testing.T) {
	ca, err := NewCA()
	if err != nil {
		t.Fatalf("NewCA returned an error: %v", err)
	}

	spiffeID := testSpiffeID
	ttl := 24 * time.Hour

	// issue certificate
	certPEM, keyPEM, err := ca.IssueCertificate(spiffeID, ttl)
	if err != nil {
		t.Fatalf("IssueCertificate returned error: %v", err)
	}

	// make sure outputs arent empty
	if len(certPEM) == 0 {
		t.Fatal("certPEM is empty")
	}

	if len(keyPEM) == 0 {
		t.Fatal("keyPEM is empty")
	}

	leafCert := parseCertPEM(t, certPEM)

	// verify signed by CA
	if leafCert.Issuer.String() != ca.Certificate.Subject.String() {
		t.Errorf("expected issuer %q, got %q",
			ca.Certificate.Subject.String(), leafCert.Issuer.String())
	}

	// verify SPIFFE ID in SAN URIs
	if len(leafCert.URIs) != 1 {
		t.Fatalf("expected 1 URI, got %d", len(leafCert.URIs))
	}
	if leafCert.URIs[0].String() != spiffeID {
		t.Errorf("expected SPIFFE ID %q, got %q", spiffeID, leafCert.URIs[0].String())
	}

	// check validity dates match ttl
	validFor := leafCert.NotAfter.Sub(leafCert.NotBefore)
	if validFor < ttl-time.Second || validFor > ttl+time.Second {
		t.Errorf("expected validity ~%v, got %v", ttl, validFor)
	}
}

func TestIssueCertificate_DifferentIDs(t *testing.T) {
	// issue first cert
	ca, err := NewCA()
	if err != nil {
		t.Fatalf("NewCA returned an error: %v", err)
	}

	spiffeID1 := testSpiffeID
	ttl := 24 * time.Hour

	certPEM1, _, err := ca.IssueCertificate(spiffeID1, ttl)
	if err != nil {
		t.Fatalf("IssueCertificate returned error: %v", err)
	}

	// issue second cert
	spiffeID2 := "spiffe://example.test/ns/default/sa/my-agent2"

	// issue certificate
	certPEM2, _, err := ca.IssueCertificate(spiffeID2, ttl)
	if err != nil {
		t.Fatalf("IssueCertificate returned error: %v", err)
	}

	// parse both certs
	leafCert1 := parseCertPEM(t, certPEM1)
	leafCert2 := parseCertPEM(t, certPEM2)

	if leafCert1.SerialNumber.Cmp(leafCert2.SerialNumber) == 0 {
		t.Error("expected different serial numbers")
	}

	pub1, ok := leafCert1.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("cert1 public key is not ECDSA")
	}
	pub2, ok := leafCert2.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("cert2 public key is not ECDSA")
	}

	b1, err := pub1.Bytes()
	if err != nil {
		t.Fatalf("cert1 public key bytes: %v", err)
	}
	b2, err := pub2.Bytes()
	if err != nil {
		t.Fatalf("cert2 public key bytes: %v", err)
	}
	sameKey := bytes.Equal(b1, b2)

	if sameKey {
		t.Error("expected different key pairs, but public keys are identical")
	}

	if leafCert1.URIs[0].String() == leafCert2.URIs[0].String() {
		t.Error("expected different SPIFFE IDs")
	}
}

func TestCertificateChainValidation(t *testing.T) {
	// create CA
	ca, err := NewCA()
	if err != nil {
		t.Fatalf("NewCA returned an error: %v", err)
	}

	spiffeID := testSpiffeID
	ttl := 24 * time.Hour

	// issue certificate
	certPEM, _, err := ca.IssueCertificate(spiffeID, ttl)
	if err != nil {
		t.Fatalf("IssueCertificate returned error: %v", err)
	}

	// parse cert
	leafCert := parseCertPEM(t, certPEM)

	// create trust pool, add the CA
	pool := x509.NewCertPool()
	pool.AddCert(ca.Certificate)

	// test chain validation
	_, err = leafCert.Verify(x509.VerifyOptions{
		Roots: pool,
	})
	if err != nil {
		t.Fatalf("chain validation failed: %v", err)
	}
}
