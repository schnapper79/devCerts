package devCerts

import (
	"bytes"

	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"math/big"
	"time"

	"golang.org/x/crypto/ssh"
)

//"go.step.sm/crypto/sshutil"

//checkWith: ssh-keygen -L -f ~/.ssh/id_rsa-cert.pub
func GetSignedCertificateSSH(alg string, cert *ssh.Certificate, parentPrivKeyPem []byte) (pubPem, privPem, certPem []byte, err error) {
	var priv interface{}
	var pub interface{}

	var sshSignerKey ssh.Signer

	switch alg {
	case "rsa":
		priv, err = rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return nil, nil, nil, err
		}
		pub = &priv.(*rsa.PrivateKey).PublicKey

		if err != nil {
			return nil, nil, nil, err
		}

	case "ec-256":
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, nil, err
		}
		pub = &priv.(*ecdsa.PrivateKey).PublicKey

		if err != nil {
			return nil, nil, nil, err
		}

	case "ec-384":
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, nil, nil, err
		}
		pub = &priv.(*ecdsa.PrivateKey).PublicKey

		if err != nil {
			return nil, nil, nil, err
		}
	case "ec-521":
		priv, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if err != nil {
			return nil, nil, nil, err
		}
		pub = &priv.(*ecdsa.PrivateKey).PublicKey

		if err != nil {
			return nil, nil, nil, err
		}
	case "ed25519":
		pub, priv, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, nil, err
		}

		if err != nil {
			return nil, nil, nil, err
		}
	default:
		return nil, nil, nil, fmt.Errorf("unknown algorithm: %s", alg)
	}

	sshSignerKey, err = ssh.ParsePrivateKey(parentPrivKeyPem)
	if err != nil {
		return nil, nil, nil, err
	}
	// create our private and public key
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, nil, nil, err
	}
	cert.Key = sshPub

	h := md5.New()

	h.Write(GetRandArray(512))

	cert.Serial = big.NewInt(0).SetBytes(h.Sum(nil)[0:8]).Uint64()

	if err := signSSHCertificate(cert, sshSignerKey); err != nil {
		return nil, nil, nil, err
	}

	caPrivKeyPEM, err := XToPem(priv, nil, true)
	if err != nil {
		return nil, nil, nil, err
	}

	pubPemSSH := marshalPublicKey(sshPub, cert.KeyId)

	certPemSSH := marshalPublicKey(cert, cert.KeyId)

	return pubPemSSH, caPrivKeyPEM, certPemSSH, nil
}

func GetUserCertificate(keyID string, ValidPrincipals []string) *ssh.Certificate {
	t := time.Now()
	cert := &ssh.Certificate{
		CertType:        ssh.UserCert,
		KeyId:           keyID,
		ValidPrincipals: ValidPrincipals,
		ValidAfter:      uint64(t.Unix()),
		ValidBefore:     uint64(t.Add(time.Hour).Unix()),
		Permissions: ssh.Permissions{
			CriticalOptions: map[string]string{},
			Extensions: map[string]string{
				"permit-X11-forwarding":   "",
				"permit-agent-forwarding": "",
				"permit-port-forwarding":  "",
				"permit-pty":              "",
				"permit-user-rc":          "",
			},
		},
		Reserved: []byte{},
	}

	return cert
}

func GetHostCertificate(keyID string, ValidPrincipals []string) *ssh.Certificate {
	t := time.Now()
	cert := &ssh.Certificate{
		CertType:        ssh.HostCert,
		KeyId:           keyID,
		ValidPrincipals: ValidPrincipals,
		ValidAfter:      uint64(t.Unix()),
		ValidBefore:     uint64(t.Add(time.Hour).Unix()),
		Permissions: ssh.Permissions{
			CriticalOptions: map[string]string{},
			Extensions:      map[string]string{},
		},
		Reserved: []byte{},
	}
	return cert
}

func signSSHCertificate(cert *ssh.Certificate, sshSigner ssh.Signer) error {
	signerKey := sshSigner.PublicKey()

	cert.SignatureKey = signerKey
	data := cert.Marshal()
	data = data[:len(data)-4]
	sig, err := sshSigner.Sign(rand.Reader, data)
	if err != nil {
		return err
	}
	cert.Signature = sig
	return nil
}

func marshalPublicKey(key ssh.PublicKey, subject string) []byte {
	b := ssh.MarshalAuthorizedKey(key)
	if i := bytes.LastIndex(b, []byte("\n")); i >= 0 {
		return append(b[:i], []byte(" "+subject+"\n")...)
	}
	return append(b, []byte(" "+subject+"\n")...)
}
