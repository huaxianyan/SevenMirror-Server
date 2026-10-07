// Package readiness probes a running relay's own /readyz endpoint.
//
// It exists because a container healthcheck runs inside the image, and these
// images ship no shell, curl or wget. The probe is therefore part of the same
// binary that serves traffic, and it asks the listener that process started.
package readiness

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"
)

const (
	probeTimeout     = 3 * time.Second
	probeDialTimeout = 2 * time.Second
)

// Options describes the listener to probe. CertificateFile is the deployment's own
// PEM chain when the listener terminates TLS, and empty for plain HTTP.
type Options struct {
	Address         string
	CertificateFile string
}

// Probe requests /readyz and requires 200. Any other status fails, including the
// 503 a relay answers when it cannot read its registry.
func Probe(options Options) error {
	if options.Address == "" {
		return errors.New("probe address is required")
	}
	scheme := "http"
	transport := &http.Transport{
		DialContext: (&net.Dialer{Timeout: probeDialTimeout}).DialContext,
	}
	if options.CertificateFile != "" {
		verify, err := pinnedCertificateVerifier(options.CertificateFile)
		if err != nil {
			return err
		}
		scheme = "https"
		transport.TLSClientConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			// The probe dials the bind address, which need not be a name in the
			// certificate, so hostname verification cannot apply. The peer is not
			// trusted blindly: VerifyPeerCertificate pins it to the chain this
			// deployment configured.
			InsecureSkipVerify:    true,
			VerifyPeerCertificate: verify,
		}
	}
	request, err := http.NewRequestWithContext(
		context.Background(), http.MethodGet, scheme+"://"+options.Address+"/readyz", nil)
	if err != nil {
		return err
	}
	client := &http.Client{
		Timeout:   probeTimeout,
		Transport: transport,
		// A failing probe must not follow a redirect to another service.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("readiness probe must not be redirected")
		},
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("readiness probe returned %s", response.Status)
	}
	return nil
}

// pinnedCertificateVerifier returns a verifier that accepts only a chain rooted in
// the certificate file the deployment configured. Expiry and signature are still
// checked, so a certificate that lapsed or was swapped fails the probe rather than
// reporting a listener that clients cannot use.
//
// This matters because the bind address is usually a loopback address while the
// certificate names a hostname, so ordinary verification would reject a healthy
// listener. Skipping verification instead would accept any certificate, including
// an expired one.
func pinnedCertificateVerifier(certificateFile string) (
	func([][]byte, [][]*x509.Certificate) error, error,
) {
	encoded, err := os.ReadFile(certificateFile)
	if err != nil {
		return nil, fmt.Errorf("read configured certificate: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(encoded) {
		return nil, fmt.Errorf("configured certificate %s contains no PEM certificate", certificateFile)
	}
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("readiness probe peer presented no certificate")
		}
		leaf, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("parse readiness probe peer certificate: %w", err)
		}
		intermediates := x509.NewCertPool()
		for _, raw := range rawCerts[1:] {
			intermediate, err := x509.ParseCertificate(raw)
			if err != nil {
				return fmt.Errorf("parse readiness probe intermediate certificate: %w", err)
			}
			intermediates.AddCert(intermediate)
		}
		// No DNSName: hostname matching is what this probe deliberately skips.
		if _, err := leaf.Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
		}); err != nil {
			return fmt.Errorf("configured certificate does not verify: %w", err)
		}
		return nil
	}, nil
}
