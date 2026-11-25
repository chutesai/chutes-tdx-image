package keyservice_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chutesai/chutes-tdx-image/keyservice"
)

// The example configuration loads once its placeholders are filled.
func TestExampleConfig(t *testing.T) {
	raw, err := os.ReadFile("config.example.json")
	if err != nil {
		t.Fatal(err)
	}
	text := strings.NewReplacer(
		"<the B64 of your 32-byte Ed25519 public key>", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"<the sha256 of your disk.tar.gz>", strings.Repeat("ab", 32),
		"<Chutes' customer-VM project number>", "487213596071").Replace(string(raw))
	path := filepath.Join(t.TempDir(), "c.json")
	_ = os.WriteFile(path, []byte(text), 0o600)
	cfg, err := keyservice.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Verify.GCEProject != "487213596071" || len(cfg.Endpoints) != 1 {
		t.Fatalf("%+v", cfg)
	}
	for _, tag := range []string{"chutes-tdx-endpoint-attest-v1", `chutes-tdx-endpoint-attest-v1\u0000x`, `chutes-tdx-endpoint-attest-v1x`, `ok\u0000tag`} {
		bad := strings.Replace(text, `"tag": "chutes-tdx-image-keyrelease-ref-v1"`, `"tag": "`+tag+`"`, 1)
		_ = os.WriteFile(path, []byte(bad), 0o600)
		if _, err := keyservice.LoadConfig(path); err == nil {
			t.Fatalf("the tag %q was accepted", tag)
		}
	}
	extra := strings.Replace(text, `"nonce_ttl_s": 60,`, `"nonce_ttl_s": 60, "skip_provenance": true,`, 1)
	_ = os.WriteFile(path, []byte(extra), 0o600)
	if _, err := keyservice.LoadConfig(path); err == nil {
		t.Fatal("an unknown key was accepted")
	}
}
