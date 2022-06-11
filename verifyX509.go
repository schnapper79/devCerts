package devCerts

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

func Verify(certPEM, rootPEM []byte, opts x509.VerifyOptions) (bool, error) {
	rootPool := x509.NewCertPool()
	intermediatesPool := x509.NewCertPool()

	ok := rootPool.AppendCertsFromPEM(rootPEM)
	if !ok {
		return false, fmt.Errorf("can't add root.pem to CertPool")
	}
	block, rest := pem.Decode([]byte(certPEM))
	if block == nil {
		return false, fmt.Errorf("failed to parse certificate PEM")
	}
	var block2 *pem.Block
	for len(rest) > 0 {
		block2, rest = pem.Decode([]byte(certPEM))
		if block == nil {
			return false, fmt.Errorf("failed to parse certificate PEM")
		}
		ok := intermediatesPool.AppendCertsFromPEM(block2.Bytes)
		if !ok {
			return false, fmt.Errorf("can't add Intermediate to CertPool")
		}
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, fmt.Errorf("failed to parse certificate: " + err.Error())
	}

	opts.Roots = rootPool
	opts.Intermediates = intermediatesPool

	if _, err := cert.Verify(opts); err != nil {
		return false, fmt.Errorf("failed to verify certificate: " + err.Error())
	}
	return true, nil
}
