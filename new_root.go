package devCerts

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
)

func GetNewRootCert(alg string, subject pkix.Name, notBefore, notAfter time.Time) (pub, priv []byte, err error) {
	// set up our CA certificate
	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// create our CA certificate
	pub, priv, err = getCertificate(alg, ca, ca, nil)
	return
}
