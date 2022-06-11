package main

import (
	"crypto"
	"crypto/x509/pkix"
	"flag"
	"io/ioutil"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/schnapper79/devCerts"
)

func main() {
	// generates a bunch of certificates to use during development and stores them into a subfolder called certs.
	var count int
	flag.IntVar(&count, "c", 1, "number of user certificates to generate")
	flag.Parse()

	// make root cert and key
	// make as many user certs as requested on command line, all valid for  one week...
	rootCert, rootKey, err := devCerts.GetNewRootCert("ec-521", pkix.Name{CommonName: "root"}, time.Now(), time.Now().AddDate(0, 0, 1))
	if err != nil {
		panic(err)
	}

	newpath := filepath.Join(".", "certs")
	err = os.MkdirAll(newpath, os.ModePerm)
	if err != nil {
		panic(err)
	}

	/*
		//check if directory is empty
		files, err := ioutil.ReadDir(newpath)
		if err != nil {
			panic(err)
		}
		if len(files) > 0 {
			panic("directory is not empty")
		}
		for _, f := range files {
			if f.IsDir() {
				panic("directory has subdirectiory: " + f.Name())
			}
		}
	*/
	err = ioutil.WriteFile(filepath.Join(newpath, "root.crt"), rootCert, 0644)
	if err != nil {
		panic(err)
	}

	//we don'T write root key to disk. if we need new certificates we renew them all at once...
	err = ioutil.WriteFile(filepath.Join(newpath, "root.key"), rootKey, 0644)
	if err != nil {
		panic(err)
	}

	rootPubCert, err := devCerts.PemToX509Cert(rootCert)
	if err != nil {
		panic(err)
	}

	rootPrivKey, err := devCerts.PemToX509Key(rootKey)
	if err != nil {
		panic(err)
	}

	for i := 0; i < count; i++ {
		//make a new HostCert and sign it................................................................
		pubPem, privPem, err := devCerts.GetNewCert(rootPubCert, rootPrivKey.(crypto.Signer), "ec-521", pkix.Name{CommonName: "testClient" + strconv.Itoa(i)}, time.Now(), time.Now().AddDate(0, 0, 1), false, []net.IP{}, []string{"localhost"}, []string{}, []*url.URL{})
		if err != nil {
			panic(err)
		}
		err = ioutil.WriteFile(filepath.Join(newpath, "client"+strconv.Itoa(i)+".crt"), pubPem, 0644)
		if err != nil {
			panic(err)
		}
		err = ioutil.WriteFile(filepath.Join(newpath, "client"+strconv.Itoa(i)+".key"), privPem, 0644)
		if err != nil {
			panic(err)
		}
	}

}
