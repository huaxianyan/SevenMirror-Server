package readiness

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// selfSigned issues a single self-signed certificate and returns the server
// certificate and the PEM file holding it.
func selfSigned(t *testing.T, notAfter time.Time) (tls.Certificate, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "sevenmirror.invalid"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		// Deliberately a name the probe will not dial, so hostname matching cannot
		// be what makes the probe pass.
		DNSNames: []string{"sevenmirror.invalid"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	file := filepath.Join(t.TempDir(), "server-cert.pem")
	if err := os.WriteFile(file, certificatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        leaf,
	}, file
}

func readyServer(t *testing.T, certificate *tls.Certificate) *httptest.Server {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/readyz" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{\"status\":\"ready\"}\n"))
	}))
	if certificate != nil {
		server.TLS.Certificates = []tls.Certificate{*certificate}
	}
	return server
}

// The listener terminates TLS on a loopback address that is not a name in the
// certificate, so ordinary verification would reject a healthy listener. This is
// the case that made a plain https probe report a working relay as unhealthy.
func TestProbeAcceptsTheConfiguredCertificateOnABindAddress(t *testing.T) {
	certificate, file := selfSigned(t, time.Now().Add(time.Hour))
	server := readyServer(t, &certificate)
	defer server.Close()

	if err := Probe(Options{
		Address:         strings.TrimPrefix(server.URL, "https://"),
		CertificateFile: file,
	}); err != nil {
		t.Fatalf("probe rejected a healthy listener: %v", err)
	}
}

// An expired certificate is a real failure: clients cannot use the listener, so a
// probe that reported ready would be wrong.
func TestProbeRejectsAnExpiredCertificate(t *testing.T) {
	certificate, file := selfSigned(t, time.Now().Add(-time.Minute))
	server := readyServer(t, &certificate)
	defer server.Close()

	err := Probe(Options{
		Address:         strings.TrimPrefix(server.URL, "https://"),
		CertificateFile: file,
	})
	if err == nil {
		t.Fatal("probe accepted an expired certificate")
	}
}

// Pinning to the configured chain means a different certificate is refused even
// though verification is not hostname-based.
func TestProbeRejectsAnUnconfiguredCertificate(t *testing.T) {
	served, _ := selfSigned(t, time.Now().Add(time.Hour))
	_, configuredFile := selfSigned(t, time.Now().Add(time.Hour))
	server := readyServer(t, &served)
	defer server.Close()

	err := Probe(Options{
		Address:         strings.TrimPrefix(server.URL, "https://"),
		CertificateFile: configuredFile,
	})
	if err == nil {
		t.Fatal("probe accepted a certificate that was not the configured one")
	}
}

func TestProbeRejectsAMissingCertificateFile(t *testing.T) {
	err := Probe(Options{
		Address:         "127.0.0.1:1",
		CertificateFile: filepath.Join(t.TempDir(), "absent.pem"),
	})
	if err == nil {
		t.Fatal("probe accepted a missing certificate file")
	}
}

// Plain HTTP is the default deployment; there is no certificate to pin.
func TestProbeOverPlainHTTP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{\"status\":\"ready\"}\n"))
	}))
	defer server.Close()

	if err := Probe(Options{Address: strings.TrimPrefix(server.URL, "http://")}); err != nil {
		t.Fatalf("probe rejected a healthy plaintext listener: %v", err)
	}
}

// The relay answers 503 when it cannot read its registry, and that must fail the
// probe rather than pass it.
func TestProbeRejectsNotReady(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("{\"status\":\"unavailable\"}\n"))
	}))
	defer server.Close()

	err := Probe(Options{Address: strings.TrimPrefix(server.URL, "http://")})
	if err == nil {
		t.Fatal("probe accepted a not-ready listener")
	}
	if !strings.Contains(err.Error(), "503") {
		t.Fatalf("error = %v, want it to name the status", err)
	}
}

// A redirect could send the probe to another service that happens to answer 200.
func TestProbeRejectsARedirect(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("{\"status\":\"ready\"}\n"))
	}))
	defer target.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer server.Close()

	err := Probe(Options{Address: strings.TrimPrefix(server.URL, "http://")})
	if err == nil {
		t.Fatal("probe followed a redirect")
	}
}

func TestProbeRejectsAnEmptyAddress(t *testing.T) {
	if err := Probe(Options{}); err == nil {
		t.Fatal("probe accepted an empty address")
	}
}

// The address must be reached over TCP: a listener that is not there is not ready.
func TestProbeReportsAnUnreachableListener(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}

	if err := Probe(Options{Address: address}); err == nil {
		t.Fatal("probe accepted an unreachable listener")
	}
}
