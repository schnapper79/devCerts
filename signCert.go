package devCerts

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

func getCertificate(alg string, template, parent *x509.Certificate, parentPrivKey interface{}) ([]byte, []byte, error) {
	var priv interface{}
	var pub interface{}
	var err error
	var pemType string
	switch alg {
	case "rsa":
		priv, err = rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return nil, nil, err
		}
		pub = &priv.(*rsa.PrivateKey).PublicKey
		pemType = "RSA PRIVATE KEY"

	case "ec-256":
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		pub = &priv.(*ecdsa.PrivateKey).PublicKey
		pemType = "EC PRIVATE KEY"

	case "ec-384":
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		pub = &priv.(*ecdsa.PrivateKey).PublicKey
		pemType = "EC PRIVATE KEY"
	case "ec-521":
		priv, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		pub = &priv.(*ecdsa.PrivateKey).PublicKey
		pemType = "EC PRIVATE KEY"
	case "ed25519":
		pub, priv, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		pemType = "ED25519 PRIVATE KEY"
	default:
		return nil, nil, fmt.Errorf("unknown algorithm: %s", alg)
	}
	// create our private and public key

	if err != nil {
		return nil, nil, err
	}

	var caBytes []byte

	if parentPrivKey != nil {
		caBytes, err = x509.CreateCertificate(rand.Reader, template, parent, pub, parentPrivKey)
	} else {
		signer, ok := priv.(crypto.Signer)
		if !ok {
			return nil, nil, fmt.Errorf("private key does not implement crypto.Signer")
		}
		caBytes, err = x509.CreateCertificate(rand.Reader, template, parent, pub, signer)
	}

	if err != nil {
		return nil, nil, err
	}

	// pem encode
	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})
	caPrivKeyPEM := new(bytes.Buffer)

	switch pemType {
	case "RSA PRIVATE KEY":
		pem.Encode(caPrivKeyPEM, &pem.Block{
			Type:  pemType,
			Bytes: x509.MarshalPKCS1PrivateKey(priv.(*rsa.PrivateKey)),
		})
	case "EC PRIVATE KEY":
		keyDer, err := x509.MarshalECPrivateKey(priv.(*ecdsa.PrivateKey))
		if err != nil {
			return nil, nil, err
		}
		pem.Encode(caPrivKeyPEM, &pem.Block{
			Type:  pemType,
			Bytes: keyDer,
		})
	case "ED25519 PRIVATE KEY":
		pem.Encode(caPrivKeyPEM, &pem.Block{
			Type:  pemType,
			Bytes: priv.(*ed25519.PrivateKey).Seed(),
		})

	}
	return caPEM.Bytes(), caPrivKeyPEM.Bytes(), nil
}
