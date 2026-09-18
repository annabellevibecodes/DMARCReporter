package secrets

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	box, err := Open("test-passphrase", "")
	if err != nil {
		t.Fatal(err)
	}
	enc, err := box.Encrypt([]byte(`{"password":"hunter2"}`))
	if err != nil {
		t.Fatal(err)
	}
	dec, err := box.Decrypt(enc)
	if err != nil {
		t.Fatal(err)
	}
	if string(dec) != `{"password":"hunter2"}` {
		t.Errorf("roundtrip = %q", dec)
	}
}

func TestKeyFileAutoCreateAndReuse(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "dmarc.key")
	box1, err := Open("", keyFile)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := box1.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(keyFile)
	if err != nil {
		t.Fatalf("key file not created: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("key file mode = %o, want 600", info.Mode().Perm())
	}

	// A second box from the same key file must decrypt data from the first.
	box2, err := Open("", keyFile)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := box2.Decrypt(enc)
	if err != nil || string(dec) != "secret" {
		t.Errorf("decrypt with reloaded key = %q, %v", dec, err)
	}
}

// TestLegacyPassphraseCiphertextStillDecrypts checks that data sealed with the
// pre-argon2 SHA-256 derivation is readable, and that new writes use the new key.
func TestLegacyPassphraseCiphertextStillDecrypts(t *testing.T) {
	const pass = "test-passphrase"
	sum := sha256.Sum256([]byte(pass))
	legacy, err := newAEAD(sum[:])
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, legacy.NonceSize())
	old := base64.StdEncoding.EncodeToString(legacy.Seal(nonce, nonce, []byte("old-secret"), nil))

	box, err := Open(pass, "")
	if err != nil {
		t.Fatal(err)
	}
	dec, err := box.Decrypt(old)
	if err != nil || string(dec) != "old-secret" {
		t.Fatalf("legacy decrypt = %q, %v", dec, err)
	}

	enc, err := box.Encrypt([]byte("new-secret"))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(enc)
	if _, err := legacy.Open(nil, raw[:legacy.NonceSize()], raw[legacy.NonceSize():], nil); err == nil {
		t.Error("new ciphertext must not be decryptable with the legacy SHA-256 key")
	}

	// A hex key has no legacy fallback.
	hexBox, err := Open(hex.EncodeToString(sum[:]), "")
	if err != nil {
		t.Fatal(err)
	}
	if hexBox.legacy != nil {
		t.Error("hex key must not set up a legacy AEAD")
	}
}

func TestDecryptGarbageFails(t *testing.T) {
	box, _ := Open("k", "")
	if _, err := box.Decrypt("bm90IHZhbGlkIGNpcGhlcnRleHQ="); err == nil {
		t.Error("expected error decrypting garbage")
	}
}
