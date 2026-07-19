package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"
)

func TestTLSConfigsRequireTLS13(t *testing.T) {
	certificate, parsed := testCertificate(t, "agent-host")
	pool := x509.NewCertPool()
	pool.AddCert(parsed)

	serverConfig := ServerTLSConfig(certificate, pool)
	if serverConfig.MinVersion != tls.VersionTLS13 || serverConfig.MaxVersion != tls.VersionTLS13 {
		t.Fatalf("server must require TLS 1.3: min=%d max=%d", serverConfig.MinVersion, serverConfig.MaxVersion)
	}
	if serverConfig.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("server must require verified client certificates, got %v", serverConfig.ClientAuth)
	}

	clientConfig, err := ClientTLSConfig(certificate, pool, "agent-host", CertificateFingerprint(parsed))
	if err != nil {
		t.Fatalf("client config: %v", err)
	}
	if clientConfig.MinVersion != tls.VersionTLS13 || clientConfig.MaxVersion != tls.VersionTLS13 {
		t.Fatalf("client must require TLS 1.3: min=%d max=%d", clientConfig.MinVersion, clientConfig.MaxVersion)
	}
}

func TestPinnedCertificateRejectsFingerprintChange(t *testing.T) {
	_, first := testCertificate(t, "agent-host")
	_, second := testCertificate(t, "agent-host")
	verify := VerifyPinnedPeer(CertificateFingerprint(first))

	if err := verify([][]byte{first.Raw}, [][]*x509.Certificate{{first}}); err != nil {
		t.Fatalf("expected matching certificate: %v", err)
	}
	if err := verify([][]byte{second.Raw}, [][]*x509.Certificate{{second}}); !errors.Is(err, ErrCertificatePinMismatch) {
		t.Fatalf("expected pin mismatch, got %v", err)
	}
}

func testCertificate(t *testing.T, commonName string) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: commonName},
		DNSNames:     []string{commonName},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey, Leaf: parsed}, parsed
}
