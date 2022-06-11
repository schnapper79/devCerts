package devCerts

import (
	"crypto/subtle"
	"log"

	"golang.org/x/crypto/ssh"
)

func ValidateSSHKey(principal string, validate, ca ssh.PublicKey) bool {
	validCert, ok := validate.(*ssh.Certificate)
	if !ok {
		log.Printf("got (%T), want *Certificate", validate)
		return false
	}
	checker := new(ssh.CertChecker)

	err := checker.CheckCert(principal, validCert)
	if err != nil {
		log.Printf("error CertChecker: %v", err)
		return false
	}

	if !KeysEqual(ca, validCert.SignatureKey) {
		fp := ssh.FingerprintSHA256(ca)
		sigFp := ssh.FingerprintSHA256(validCert.SignatureKey)
		log.Printf("fp soll: %v, ist: %v", fp, sigFp)
		return false
	}
	return true
}

// KeysEqual is constant time compare of the keys to avoid timing attacks.
func KeysEqual(ak, bk ssh.PublicKey) bool {
	//avoid panic if one of the keys is nil, return false instead
	if ak == nil || bk == nil {
		return false
	}

	a := ak.Marshal()
	b := bk.Marshal()
	return (len(a) == len(b) && subtle.ConstantTimeCompare(a, b) == 1)
}
