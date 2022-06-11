package devCerts

import (
	"crypto/x509"
	"encoding/pem"

	"go.step.sm/crypto/pemutil"
)

func PemToX509Cert(certBytes []byte) (*x509.Certificate, error) {
	return pemutil.ParseCertificate(certBytes)
}

func PemToX509Key(keyBytes []byte, opts ...pemutil.Options) (interface{}, error) {
	return pemutil.ParseKey(keyBytes, opts...)
}

func DecryptPem(pemBytes []byte, password []byte) ([]byte, error) {
	pemBlock, _ := pem.Decode(pemBytes)
	pb, err := pemutil.DecryptPEMBlock(pemBlock, password)
	if err != nil {
		return nil, err
	}
	return pb, nil
}

func XToPem(input interface{}, pw []byte, withOpenSSH bool) ([]byte, error) {
	options := make([]pemutil.Options, 0)
	options = append(options, pemutil.WithOpenSSH(withOpenSSH))
	if pw != nil {
		options = append(options, pemutil.WithPassword(pw))
	}
	pb, err := pemutil.Serialize(input, options...)
	if err != nil {
		return nil, err
	}
	return pb.Bytes, nil
}
