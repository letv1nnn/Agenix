package certutil

import (
	"testing"
)

// constants for testing
const (
	trustDomainExample    = "example.org"
	namespaceDefault      = "default"
	serviceAccountExample = "my-agent"
)

func TestGenerateSPIFFEID(t *testing.T) {
	id, err := GenerateSPIFFEID(trustDomainExample, namespaceDefault, "weather-agent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := "spiffe://example.org/ns/default/sa/weather-agent"
	if id != expected {
		t.Errorf("expected %q, got %q", expected, id)
	}
}

func TestGenerateSPIFFEID_EmptyInputs(t *testing.T) {
	tests := []struct {
		name           string
		trustDomain    string
		namespace      string
		serviceAccount string
	}{
		{"empty trust domain", "", namespaceDefault, serviceAccountExample},
		{"empty namespace", trustDomainExample, "", serviceAccountExample},
		{"empty service account", trustDomainExample, namespaceDefault, ""},
		{"whitespace-only namespace", trustDomainExample, "   ", serviceAccountExample},
		{"whitespace-only service account", trustDomainExample, namespaceDefault, "   "},
		{"namespace with slash", trustDomainExample, "ns/bad", serviceAccountExample},
		{"service account with slash", trustDomainExample, namespaceDefault, "sa/bad"},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := GenerateSPIFFEID(testCase.trustDomain, testCase.namespace, testCase.serviceAccount)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestParseSPIFFEID(t *testing.T) {
	id, err := GenerateSPIFFEID(trustDomainExample, "production", "payment-agent")
	if err != nil {
		t.Fatalf("generate failed: %v", err)
	}

	td, ns, sa, err := ParseSPIFFEID(id)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	if td != trustDomainExample {
		t.Errorf("expected trust domain %q, got %q", trustDomainExample, td)
	}
	if ns != "production" {
		t.Errorf("expected namespace %q, got %q", "production", ns)
	}
	if sa != "payment-agent" {
		t.Errorf("expected service account %q, got %q", "payment-agent", sa)
	}
}

func TestParseSPIFFEID_InvalidFormat(t *testing.T) {
	tests := []struct {
		name string
		id   string
	}{
		{"missing scheme", trustDomainExample + "/ns/default/sa/agent"},
		{"wrong scheme", "https://" + trustDomainExample + "/ns/default/sa/agent"},
		{"missing ns segment", "spiffe://" + trustDomainExample + "/default/sa/agent"},
		{"missing sa segment", "spiffe://" + trustDomainExample + "/ns/default/agent"},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			_, _, _, err := ParseSPIFFEID(testCase.id)
			if err == nil {
				t.Errorf("expected error for %q, got nil", testCase.id)
			}
		})
	}
}
