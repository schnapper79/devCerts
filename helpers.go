package devCerts

import (
	"crypto/rand"
	"os"
	"path/filepath"
)

func GetAbsDir() string {
	var dirAbsPath string
	ex, err := os.Executable()
	if err == nil {
		exReal, err := filepath.EvalSymlinks(ex)
		if err != nil {
			panic(err)
		}
		dirAbsPath = filepath.Dir(exReal)
	}
	return dirAbsPath
}

func GetRandArray(size int) []byte {
	b := make([]byte, size)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return b
}
