package authority

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

type Certificate struct {
	privateKey     *ecdsa.PrivateKey
	certificateDER []byte
	privateDER     []byte
	CertificatePEM []byte
	PrivatePEM     []byte
}

func IssueCACrt() (*Certificate, error) {
	caPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("authority: CA generate private key: %s", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(time.Hour)
	caTemplate := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "my-ca"},
		SerialNumber:          big.NewInt(1),
		BasicConstraintsValid: true,
		IsCA:                  true,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage: x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDigitalSignature |
			x509.KeyUsageCertSign,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPriv.Public(), caPriv)
	if err != nil {
		return nil, fmt.Errorf("authority: CA create x509 certificate: %s", err)
	}

	caPrivDER, err := x509.MarshalECPrivateKey(caPriv)
	if err != nil {
		return nil, fmt.Errorf("authority: CA marshal ec private key: %s", err)
	}

	// used to save to file
	caCertPEM := pem.EncodeToMemory(&pem.Block{Bytes: caCertDER, Type: "CERTIFICATE"})
	caPrivPEM := pem.EncodeToMemory(&pem.Block{Bytes: caPrivDER, Type: "EC PRIVATE KEY"})

	return &Certificate{
		privateKey:     caPriv,
		certificateDER: caCertDER,
		privateDER:     caPrivDER,
		CertificatePEM: caCertPEM,
		PrivatePEM:     caPrivPEM,
	}, nil
}

func IssueServerCrt(CACertificate *Certificate) (*Certificate, error) {
	caCert, err := x509.ParseCertificate(CACertificate.certificateDER)
	if err != nil {
		return nil, fmt.Errorf("authority: Server parse certificate: %s", err)
	}

	srvPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("authority: Server generate private key: %s", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(time.Hour)
	srvCrtTemplate := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "my-server"},
		SerialNumber: big.NewInt(2),
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		DNSNames:     []string{"localhost"},
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	srvCrtDER, err := x509.CreateCertificate(rand.Reader, srvCrtTemplate, caCert, srvPrivKey.Public(), CACertificate.privateKey)
	if err != nil {
		return nil, fmt.Errorf("authority: Server create certificate: %s", err)
	}

	srvPrivKeyDER, err := x509.MarshalECPrivateKey(srvPrivKey)
	if err != nil {
		return nil, fmt.Errorf("authority: Server marshal ec private key: %s", err)
	}

	// used to save to file
	srvCertPEM := pem.EncodeToMemory(&pem.Block{Bytes: srvCrtDER, Type: "CERTIFICATE"})
	srvPrivPEM := pem.EncodeToMemory(&pem.Block{Bytes: srvPrivKeyDER, Type: "EC PRIVATE KEY"})

	return &Certificate{
		privateKey:     srvPrivKey,
		certificateDER: srvCrtDER,
		privateDER:     srvPrivKeyDER,
		CertificatePEM: srvCertPEM,
		PrivatePEM:     srvPrivPEM,
	}, nil
}

func IssueClientCrt(CACertificate *Certificate) (*Certificate, error) {
	caCert, err := x509.ParseCertificate(CACertificate.certificateDER)
	if err != nil {
		return nil, fmt.Errorf("authority: Client parse certificate: %s", err)
	}

	clientPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("authority: Client generate private key: %s", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(time.Hour)
	clientTemplate := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "my-client"},
		SerialNumber: big.NewInt(3),
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	clientCertDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, clientPrivKey.Public(), CACertificate.privateKey)
	if err != nil {
		return nil, fmt.Errorf("authority: Client create certificate: %s", err)
	}
	clientPrivDER, err := x509.MarshalECPrivateKey(clientPrivKey)
	if err != nil {
		return nil, fmt.Errorf("authority: Client marshal certificate: %s", err)
	}

	clientCertPEM := pem.EncodeToMemory(&pem.Block{Bytes: clientCertDER, Type: "CERTIFICATE"})
	clientPrivPEM := pem.EncodeToMemory(&pem.Block{Bytes: clientPrivDER, Type: "EC PRIVATE KEY"})

	return &Certificate{
		privateKey:     clientPrivKey,
		certificateDER: clientCertDER,
		privateDER:     clientPrivDER,
		CertificatePEM: clientCertPEM,
		PrivatePEM:     clientPrivPEM,
	}, nil
}
