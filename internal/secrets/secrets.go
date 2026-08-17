// Package secrets encrypts account credentials at rest with AES-256-GCM.
// The key comes from the SECRETS_KEY environment variable, or — when unset —
// from an auto-generated key file stored next to the database.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
)

// Box encrypts and decrypts small secret payloads.
type Box struct {
	aead cipher.AEAD
}

// Open builds a Box. If envKey is non-empty it is used (64-char hex is taken
// as a raw 32-byte key, anything else is hashed with SHA-256). Otherwise the
// key is read from keyFile, which is created with a random key on first use.
func Open(envKey, keyFile string) (*Box, error) {
	var key []byte
	switch {
	case envKey != "":
		if raw, err := hex.DecodeString(envKey); err == nil && len(raw) == 32 {
			key = raw
		} else {
			sum := sha256.Sum256([]byte(envKey))
			key = sum[:]
		}
	default:
		var err error
		key, err = loadOrCreateKeyFile(keyFile)
		if err != nil {
			return nil, err
		}
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{aead: aead}, nil
}

func loadOrCreateKeyFile(path string) ([]byte, error) {
	if data, err := os.ReadFile(path); err == nil {
		key, err := hex.DecodeString(string(trimSpace(data)))
		if err != nil || len(key) != 32 {
			return nil, fmt.Errorf("key file %s is corrupt (expected 64 hex chars)", path)
		}
		return key, nil
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(key)+"\n"), 0o600); err != nil {
		return nil, fmt.Errorf("write key file %s: %w", path, err)
	}
	return key, nil
}

func trimSpace(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r' || b[len(b)-1] == ' ') {
		b = b[:len(b)-1]
	}
	return b
}

// Encrypt seals plaintext and returns base64(nonce || ciphertext).
func (b *Box) Encrypt(plaintext []byte) (string, error) {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := b.aead.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// Decrypt reverses Encrypt.
func (b *Box) Decrypt(encoded string) ([]byte, error) {
	sealed, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	ns := b.aead.NonceSize()
	if len(sealed) < ns {
		return nil, fmt.Errorf("ciphertext too short")
	}
	return b.aead.Open(nil, sealed[:ns], sealed[ns:], nil)
}
