package devCerts

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"net/url"
	"testing"
	"time"
)

func Test_GetNewRootCert(t *testing.T) {
	// 1) get a new root cert
	rootPubPEM, rootPrivPEM, err := GetNewRootCert("rsa", pkix.Name{CommonName: "testroot"}, time.Now(), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	rootPubCert, err := PemToX509Cert(rootPubPEM)
	if err != nil {
		t.Fatal(err)
	}

	rootPrivKey, err := PemToX509Key(rootPrivPEM)
	if err != nil {
		t.Fatal(err)
	}

	clientPubPEM, _, err := GetNewCert(rootPubCert, rootPrivKey.(crypto.Signer), "rsa", pkix.Name{CommonName: "testclient"}, time.Now(), time.Now().Add(time.Hour), false, []net.IP{}, []string{"localhost"}, []string{}, []*url.URL{})
	if err != nil {
		t.Fatal(err)
	}

	ok, err := Verify(clientPubPEM, rootPubPEM, x509.VerifyOptions{DNSName: "localhost"})
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("verify failed...")
	}
}
