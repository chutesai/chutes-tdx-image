package keyfetch_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/chutesai/chutes-tdx-image/internal/appkey"
	"github.com/chutesai/chutes-tdx-image/keyfetch"
	"github.com/chutesai/chutes-tdx-image/keyservice"
)

// testCA is a self-signed certificate (LoadConfig needs one).
func testCA(t *testing.T) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func released(b byte) []byte { return bytes.Repeat([]byte{b}, 64) }

func config(t *testing.T, edit func(map[string]any)) (*keyfetch.Config, error) {
	t.Helper()
	ctx := appkey.Context(released(1), sha256.Sum256([]byte("app")))
	key, _ := appkey.DataKey(released(1), ctx)
	kcv := appkey.KCV(key)
	doc := map[string]any{"server_name": "keys.test.invalid", "ca_pem": testCA(t), "tag": "chutes-tdx-image-keyrelease-ref-v1",
		"app_context": hex.EncodeToString(ctx[:]), "app_kcv": hex.EncodeToString(kcv[:])}
	if edit != nil {
		edit(doc)
	}
	raw, _ := json.Marshal(doc)
	path := filepath.Join(t.TempDir(), "c.json")
	_ = os.WriteFile(path, raw, 0o600)
	return keyfetch.LoadConfig(path)
}

func TestConfig(t *testing.T) {
	if _, err := config(t, nil); err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(map[string]any){
		"no context":       func(d map[string]any) { delete(d, "app_context") },
		"no kcv":           func(d map[string]any) { delete(d, "app_kcv") },
		"short kcv":        func(d map[string]any) { d["app_kcv"] = "abcd" },
		"upper-case kcv":   func(d map[string]any) { d["app_kcv"] = "AB" + d["app_kcv"].(string)[2:] },
		"extra key":        func(d map[string]any) { d["x"] = 1 },
		"the gate's tag":   func(d map[string]any) { d["tag"] = "chutes-tdx-endpoint-attest-v1" },
		"the gate's tag+":  func(d map[string]any) { d["tag"] = "chutes-tdx-endpoint-attest-v1\x00x" },
		"a NUL in the tag": func(d map[string]any) { d["tag"] = "a\x00b" },
	} {
		if _, err := config(t, edit); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The released key is checked before cryptsetup: the image's own owner key gives its data key;
// another one is key_check_failed.
func TestDataKeyChecked(t *testing.T) {
	cfg, err := config(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	key, err := cfg.DataKey(released(1))
	ctx := appkey.Context(released(1), sha256.Sum256([]byte("app")))
	want, _ := appkey.DataKey(released(1), ctx)
	if err != nil || !bytes.Equal(key, want) {
		t.Fatalf("%v", err)
	}
	if _, err := cfg.DataKey(released(2)); !errors.Is(err, keyfetch.ErrKeyCheck) {
		t.Fatalf("another owner key: %v", err)
	}
}

// One attempt outlasts the reference service's verification, so a slow one is not abandoned
// (each abandoned attempt spends one of the key window's four connections).
func TestAttemptOutlastsVerification(t *testing.T) {
	if keyfetch.AttemptTimeout < keyservice.VerifyTimeout+30*time.Second {
		t.Fatalf("an attempt lasts %s, a verification up to %s", keyfetch.AttemptTimeout, keyservice.VerifyTimeout)
	}
}
