package certutil

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// pattern that describes SPIFFE ID
var validTrustDomain = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$`)

func GenerateSPIFFEID(trustDomain, namespace, serviceAccount string) (string, error) {
	trustDomain = strings.TrimSpace(trustDomain)
	namespace = strings.TrimSpace(namespace)
	serviceAccount = strings.TrimSpace(serviceAccount)

	if trustDomain == "" {
		return "", fmt.Errorf("trust domain cannot be empty")
	}
	if namespace == "" {
		return "", fmt.Errorf("namespace cannot be empty")
	}
	if serviceAccount == "" {
		return "", fmt.Errorf("service account cannot be empty")
	}

	if strings.Contains(namespace, "/") {
		return "", fmt.Errorf("invalid namespace %q: must not contain '/'", namespace)
	}
	if strings.Contains(serviceAccount, "/") {
		return "", fmt.Errorf("invalid service account %q: must not contain '/'", serviceAccount)
	}

	// validating the trust domain follows SPIFFE spec
	if !validTrustDomain.MatchString(trustDomain) {
		return "", fmt.Errorf("invalid trust domain %q: must contain only lowercase DNS characters", trustDomain)
	}

	return fmt.Sprintf("spiffe://%s/ns/%s/sa/%s", trustDomain, namespace, serviceAccount), nil
}

// function to extract trust domain, namespace and service account from SPIFFE ID
func ParseSPIFFEID(spiffeID string) (trustDomain, namespace, serviceAccount string, err error) {
	parsed, err := url.Parse(spiffeID)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to parse SPIFFE ID: %w", err)
	}

	if parsed.Scheme != "spiffe" {
		return "", "", "", fmt.Errorf("invalid scheme %q: must be spiffe", parsed.Scheme)
	}
	if parsed.Host == "" {
		return "", "", "", fmt.Errorf("missing trust domain")
	}

	parts := strings.Split(parsed.Path, "/")
	if len(parts) != 5 || parts[1] != "ns" || parts[3] != "sa" {
		return "", "", "", fmt.Errorf("invalid SPIFFE ID path %q: expected /ns/<namespace>/sa/<serviceAccount>", parsed.Path)
	}
	if parts[2] == "" || parts[4] == "" {
		return "", "", "", fmt.Errorf("namespace and service account cannot be empty")
	}

	return parsed.Host, parts[2], parts[4], nil
}
