package devCerts

import (
	"crypto"
	"crypto/md5"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/url"
	"time"
)

func GetNewCert(parent *x509.Certificate, parentPrivKey crypto.Signer, alg string, subject pkix.Name, notBefore, notAfter time.Time, isCA bool, ipAdresses []net.IP, DNSNames, EmailAddresses []string, URIs []*url.URL) (pub, priv []byte, err error) {
	// set up our CA certificate
	ca := &x509.Certificate{
		Subject:               subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  isCA,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if isCA {
		ca.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
	} else {
		ca.KeyUsage = x509.KeyUsageDigitalSignature
		ca.IPAddresses = ipAdresses
		ca.DNSNames = DNSNames
		ca.EmailAddresses = EmailAddresses
		ca.URIs = URIs
	}

	h := md5.New()
	h.Write(ca.Raw)
	h.Write(GetRandArray(512))

	ca.SerialNumber = big.NewInt(0).SetBytes(h.Sum(nil))

	// create our CA certificate
	pub, priv, err = getCertificate(alg, ca, parent, parentPrivKey)

	return
}
