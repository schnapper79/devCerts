package devCerts

import (
	"golang.org/x/crypto/ssh"
)

func PublicPemToSsh(pem []byte) (ssh.PublicKey, error) {
	sshKey, _, _, _, err := ssh.ParseAuthorizedKey(pem)
	return sshKey, err
}

func PrivatePemToSsh(pem []byte) (ssh.Signer, error) {
	signer, err := ssh.ParsePrivateKey(pem)
	if err != nil {
		return nil, err
	}

	return signer, nil
}
