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
	"errors"
	"fmt"
	"os"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters for passphrase-derived keys (RFC 9106 second
// recommended option: 64 MiB, 3 passes, 4 lanes).
const (
	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 4
)

// kdfSalt is a fixed application salt. Passphrase keys are per deployment and
// there is no place to persist a random salt before the database is open, so
// the salt only serves to make precomputed tables app-specific; the work
// factor comes from argon2id.
var kdfSalt = []byte("dmarcreporter/secrets/v2")

// Box encrypts and decrypts small secret payloads.
type Box struct {
	aead cipher.AEAD
	// legacy is set only for passphrase keys: it is the pre-v2 SHA-256
	// derived key, tried on decrypt so data written by older versions still
	// opens. Encrypt always uses aead, so re-saving a secret migrates it.
	legacy cipher.AEAD
}

// Open builds a Box. If envKey is non-empty it is used: a 64-char hex string
// is taken as a raw 32-byte key; anything else is treated as a passphrase and
// stretched with argon2id. Otherwise the key is read from keyFile, which is
// created with a random key on first use.
func Open(envKey, keyFile string) (*Box, error) {
	var key, legacyKey []byte
	switch {
	case envKey != "":
		if raw, err := hex.DecodeString(envKey); err == nil && len(raw) == 32 {
			key = raw
		} else {
			key = argon2.IDKey([]byte(envKey), kdfSalt, argonTime, argonMemory, argonThreads, 32)
			sum := sha256.Sum256([]byte(envKey))
			legacyKey = sum[:]
		}
	default:
		var err error
		key, err = loadOrCreateKeyFile(keyFile)
		if err != nil {
			return nil, err
		}
	}

	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	b := &Box{aead: aead}
	if legacyKey != nil {
		if b.legacy, err = newAEAD(legacyKey); err != nil {
			return nil, err
		}
	}
	return b, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
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

// Decrypt reverses Encrypt. For passphrase keys, ciphertext written by
// versions that used the old SHA-256 derivation is still accepted.
func (b *Box) Decrypt(encoded string) ([]byte, error) {
	sealed, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	ns := b.aead.NonceSize()
	if len(sealed) < ns {
		return nil, fmt.Errorf("ciphertext too short")
	}
	plain, err := b.aead.Open(nil, sealed[:ns], sealed[ns:], nil)
	if err == nil || b.legacy == nil {
		return plain, err
	}
	if plain, lerr := b.legacy.Open(nil, sealed[:ns], sealed[ns:], nil); lerr == nil {
		return plain, nil
	}
	return nil, errors.New("cipher: message authentication failed")
}
