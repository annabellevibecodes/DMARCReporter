package secrets

import (
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

func TestDecryptGarbageFails(t *testing.T) {
	box, _ := Open("k", "")
	if _, err := box.Decrypt("bm90IHZhbGlkIGNpcGhlcnRleHQ="); err == nil {
		t.Error("expected error decrypting garbage")
	}
}
