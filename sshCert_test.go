package devCerts

import (
	"crypto/x509/pkix"
	"fmt"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestPemToSshSigner(t *testing.T) {
	// 1) get a new root cert
	_, priv, err := GetNewRootCert("ec-521", pkix.Name{CommonName: "test"}, time.Now(), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	//try using this one as a signer
	signer, err := PrivatePemToSsh(priv)
	if err != nil {
		t.Fatal(err)
	}
	sshPubKey := ssh.MarshalAuthorizedKey(signer.PublicKey())
	fmt.Println(string(sshPubKey))
	fmt.Println(ssh.FingerprintSHA256(signer.PublicKey()))

	//make a new HostCert and sign it................................................................
	crt := GetHostCertificate("testHost", []string{"testHost", "testHost.local"})
	_, _, certPem, err := GetSignedCertificateSSH("ec-521", crt, priv)

	if err != nil {
		t.Fatal(err)
	}
	//try PemToKey (let's try at least)
	sshKey2, err := PublicPemToSsh(certPem)
	if err != nil {
		t.Fatal("PemToKey", err)
	}
	erg := ValidateSSHKey("testHost", sshKey2, signer.PublicKey())
	if !erg {
		t.Fatal("sshValidateSSHKey2 not valid")
	}

	//Test with another root certificate
	_, priv2, err := GetNewRootCert("ec-521", pkix.Name{CommonName: "test"}, time.Now(), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	//try using this one as a signer
	signer2, err := PrivatePemToSsh(priv2)
	if err != nil {
		t.Fatal(err)
	}
	erg = ValidateSSHKey("testHost", sshKey2, signer2.PublicKey())
	if erg {
		t.Fatal("sshValidateSSHKey2 shouldn't be valid")
	}

}
