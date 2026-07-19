package transport

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

var ErrCertificatePinMismatch = errors.New("peer certificate fingerprint mismatch")

func CertificateFingerprint(certificate *x509.Certificate) string {
	if certificate == nil {
		return ""
	}
	digest := sha256.Sum256(certificate.Raw)
	return hex.EncodeToString(digest[:])
}

func ServerTLSConfig(certificate tls.Certificate, clientCAs *x509.CertPool) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		ClientCAs:    clientCAs,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
}

func ClientTLSConfig(
	certificate tls.Certificate,
	roots *x509.CertPool,
	serverName string,
	expectedFingerprint string,
) (*tls.Config, error) {
	if strings.TrimSpace(expectedFingerprint) == "" {
		return nil, errors.New("expected certificate fingerprint is required")
	}
	return &tls.Config{
		MinVersion:            tls.VersionTLS13,
		MaxVersion:            tls.VersionTLS13,
		Certificates:          []tls.Certificate{certificate},
		RootCAs:               roots,
		ServerName:            serverName,
		VerifyPeerCertificate: VerifyPinnedPeer(expectedFingerprint),
	}, nil
}

func VerifyPinnedPeer(expectedFingerprint string) func([][]byte, [][]*x509.Certificate) error {
	expected := normalizeFingerprint(expectedFingerprint)
	return func(rawCertificates [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCertificates) == 0 {
			return fmt.Errorf("%w: certificate chain is empty", ErrCertificatePinMismatch)
		}
		certificate, err := x509.ParseCertificate(rawCertificates[0])
		if err != nil {
			return fmt.Errorf("parse peer certificate: %w", err)
		}
		actual := normalizeFingerprint(CertificateFingerprint(certificate))
		if actual != expected {
			return fmt.Errorf("%w: expected %s, got %s", ErrCertificatePinMismatch, expected, actual)
		}
		return nil
	}
}

func normalizeFingerprint(value string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), ":", ""))
}
