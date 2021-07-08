package cert

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"sync"
)

var (
	/*
	 * tlsCipherSuites is the list of cipher suites we accept for TLS
	 * connections. These cipher suites fit the following criteria:
	 * - Don't use outdated algorithms like SHA-1 and 3DES
	 * - Don't use ECB mode or other insecure symmetric methods
	 * - Included in the TLS v1.2 suite
	 * - Are available in the Go 1.7.6 standard library (more are
	 *   available in 1.8.3 and will be added after lnd no longer
	 *   supports 1.7, including suites that support CBC mode)
	**/
	tlsCipherSuites = []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	}
)

type TlsReloader struct {
	certMu sync.RWMutex
	cert   *tls.Certificate
}

// GetCertBytesFromPath reads the TLS certificate and key files at the given
// certPath and keyPath and returns the file bytes.
func GetCertBytesFromPath(certPath, keyPath string) (certBytes, keyBytes []byte, err error) {
	certBytes, err = ioutil.ReadFile(certPath)
	if err != nil {
		return nil, nil, err
	}
	keyBytes, err = ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, nil, err
	}
	return certBytes, keyBytes, nil
}

// LoadCert loads a certificate and its corresponding private key from the PEM
// bytes indicated and returns the certificate in the two formats it is most
// commonly used.
func LoadCert(certBytes, keyBytes []byte) (tls.Certificate, *x509.Certificate,
	error) {

	// The certData returned here is just a wrapper around the PEM blocks
	// loaded from the file. The PEM is not yet fully parsed but a basic
	// check is performed that the certificate and private key actually
	// belong together.
	certData, err := tls.X509KeyPair(certBytes, keyBytes)
	if err != nil {
		return tls.Certificate{}, nil, err
	}

	// Now parse the the PEM block of the certificate into its x509 data
	// structure so it can be examined in more detail.
	x509Cert, err := x509.ParseCertificate(certData.Certificate[0])
	if err != nil {
		return tls.Certificate{}, nil, err
	}

	return certData, x509Cert, nil
}

// TLSConfFromCert returns the default TLS configuration used for a server,
// using the given certificate as identity.
func TLSConfFromCert(certData tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{certData},
		CipherSuites: tlsCipherSuites,
		MinVersion:   tls.VersionTLS12,
	}
}

// NewTLSReloader is used to create a new TLS Reloader that will be used
// to update the TLS certificate without restarting the server.
func NewTLSReloader(certBytes, keyBytes []byte) (*TlsReloader, error) {
	result := &TlsReloader{}
	cert, _, err := LoadCert(certBytes, keyBytes)
	if err != nil {
		return nil, err
	}
	result.cert = &cert
	return result, nil
}

// AttemptReload will make an attempt to update the TLS certificate
// and key used by the server.
func (tlsr *TlsReloader) AttemptReload(certBytes, keyBytes []byte) error {
	newCert, _, err := LoadCert(certBytes, keyBytes)
	if err != nil {
		return err
	}
	tlsr.certMu.Lock()
	defer tlsr.certMu.Unlock()
	tlsr.cert = &newCert
	return nil
}

// GetCertificateFunc is used in the server's TLS configuration to
// determine the correct TLS certificate to server on a request.
func (tlsr *TlsReloader) GetCertificateFunc() func(*tls.ClientHelloInfo) (
	*tls.Certificate, error) {
	return func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		tlsr.certMu.RLock()
		defer tlsr.certMu.RUnlock()
		return tlsr.cert, nil
	}
}
