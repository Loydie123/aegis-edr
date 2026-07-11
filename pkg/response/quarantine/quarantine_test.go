package quarantine

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"os"
	"path/filepath"
	"testing"
)

func TestQuarantineFile(t *testing.T) {
	t.Parallel()

	key := []byte("12345678901234567890123456789012")
	payload := []byte("this is a malicious file payload to block")

	tmpDir, err := os.MkdirTemp("", "aegis_quar_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	srcPath := filepath.Join(tmpDir, "malicious.exe")
	if err := os.WriteFile(srcPath, payload, 0644); err != nil {
		t.Fatal(err)
	}

	destDir := filepath.Join(tmpDir, "quarantine")
	q := NewQuarantiner(key)

	if err := q.QuarantineFile(srcPath, destDir); err != nil {
		t.Fatalf("expected QuarantineFile to succeed, got %v", err)
	}

	if _, err := os.Stat(srcPath); !os.IsNotExist(err) {
		t.Error("expected original source file to be removed, but it still exists")
	}

	destPath := filepath.Join(destDir, "malicious.exe.quarantine")
	encryptedData, err := os.ReadFile(destPath)
	if err != nil {
		t.Fatalf("failed to read quarantined file: %v", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}

	nonceSize := gcm.NonceSize()
	if len(encryptedData) < nonceSize {
		t.Fatal("encrypted data is too short")
	}

	nonce := encryptedData[:nonceSize]
	ciphertext := encryptedData[nonceSize:]

	decrypted, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		t.Fatalf("failed to decrypt quarantined file data: %v", err)
	}

	if !bytes.Equal(decrypted, payload) {
		t.Errorf("expected decrypted data %s, got %s", payload, decrypted)
	}
}
