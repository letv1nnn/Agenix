package ca

import (
	"bytes"
	"encoding/pem"
	"errors"
	"time"

	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix" // for 'Subject:' in cert

	"math/big" // for serial number
	"net/url"  // for spiffe
)

type CA struct {
	PrivateKey     *ecdsa.PrivateKey
	Certificate    *x509.Certificate
	CertificatePem []byte // CA certificate in PEM encoded bytes
}

func randomSerialNumber() (*big.Int, error) {
	// generate a random serial number
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, serialLimit)
}

func EncodeCertPEM(derBytes []byte) []byte {
	var buf bytes.Buffer
	_ = pem.Encode(&buf, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})
	return buf.Bytes()
}

func EncodeKeyPEM(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: der,
	}); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func NewCA() (*CA, error) {
	// generate a random serial number
	serialNumber, err := randomSerialNumber()
	if err != nil {
		return nil, err
	}

	// set time to now
	now := time.Now()

	// certificate template
	certTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "Agenix CA", // CN=Agenix CA
		},
		NotBefore:             now,
		NotAfter:              now.AddDate(10, 0, 0), // 10 years
		IsCA:                  true,
		BasicConstraintsValid: true, // suggested for inclusion by Cursor
		KeyUsage:              x509.KeyUsageCertSign,
	}

	// generate ecdsa p-256 key pair
	curve := elliptic.P256()
	certPrivateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}

	// create self-signed certificate
	caBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &certPrivateKey.PublicKey, certPrivateKey)
	if err != nil {
		return nil, err
	}

	certificate, err := x509.ParseCertificate(caBytes)
	if err != nil {
		return nil, err
	}

	certPem := EncodeCertPEM(caBytes)

	// return CA struct
	return &CA{
		PrivateKey:     certPrivateKey,
		Certificate:    certificate,
		CertificatePem: certPem,
	}, nil
}

func (ca *CA) IssueCertificate(spiffeID string, ttl time.Duration) (certPEM []byte, keyPEM []byte, err error) { // signs a new leaf certificate
	// generate random serial number
	serialNumber, err := randomSerialNumber()
	if err != nil {
		return nil, nil, err
	}

	// parse SpiffeID into url
	if spiffeID == "" {
		return nil, nil, errors.New("spiffeID cannot be empty")
	}
	parsed, err := url.Parse(spiffeID)
	if err != nil {
		return nil, nil, err
	}

	// set time to now
	now := time.Now()

	// leaf certificate template
	leafTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		URIs:         []*url.URL{parsed},
		NotBefore:    now,
		NotAfter:     now.Add(ttl),
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
	}

	// generate a new ECDSA P-256 key pair for the leaf
	curve := elliptic.P256()
	leafPrivateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	// create certificate
	leafBytes, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca.Certificate, &leafPrivateKey.PublicKey, ca.PrivateKey)
	if err != nil {
		return nil, nil, err
	}

	// encode cert and key
	certPem := EncodeCertPEM(leafBytes)
	keyPem, err := EncodeKeyPEM(leafPrivateKey)
	if err != nil {
		return nil, nil, err
	}

	// return cert and key as pem encoded bytes
	return certPem, keyPem, nil
}
