package quarantine

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
)

type Quarantiner struct {
	key []byte
}

func NewQuarantiner(key []byte) *Quarantiner {
	return &Quarantiner{key: key}
}

func (q *Quarantiner) QuarantineFile(srcPath, destDir string) error {
	data, err := os.ReadFile(srcPath)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(q.key)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	encrypted := gcm.Seal(nonce, nonce, data, nil)

	if err := os.MkdirAll(destDir, 0700); err != nil {
		return err
	}

	filename := filepath.Base(srcPath) + ".quarantine"
	destPath := filepath.Join(destDir, filename)

	if err := os.WriteFile(destPath, encrypted, 0400); err != nil {
		return err
	}

	return os.Remove(srcPath)
}
