// Package keyrel is the reference key-release protocol between the VM (chutes-key-fetch) and the
// owner's key service (chutes-key-service), over one TLS 1.3 connection that runs end to end
// through Chutes' key relay:
//
//	GET  /v1/nonce    -> {"nonce": "<64 hex>"}
//	POST /v1/release  {"nonce", "quote_b64", "endpoint_id", "instance": {"project_number", "zone",
//	                   "instance_id"}} -> {"key_b64"}
//
// The quote's REPORTDATA is SHA-512(tag || 0x00 || nonce (32 bytes) || exporter (32 bytes) ||
// endpoint_id (the 36 ASCII bytes of the metadata attribute chutes-endpoint-id)), where exporter is
// the connection's TLS exported keying material (label EXPORTER-chutes-tdx-key-release, no
// context, 32 bytes). The tag is never the gate's /attest tag.
//
// This protocol is a reference: an owner's key service may use its own.
package keyrel

import (
	"crypto/sha512"
	"crypto/tls"
	"errors"
	"regexp"
	"strings"
)

const (
	// DefaultTag is the reference REPORTDATA tag (never chutes-tdx-endpoint-attest-v1).
	DefaultTag = "chutes-tdx-image-keyrelease-ref-v1"
	// GateTag is the endpoint's /attest tag: refused as a key-release tag (domain separation).
	GateTag = "chutes-tdx-endpoint-attest-v1"
	// ExporterLabel is the TLS exporter label.
	ExporterLabel = "EXPORTER-chutes-tdx-key-release"
	// KeySize is the app partition's dm-crypt key (aes-xts-plain64, 512 bits).
	KeySize = 64
)

var endpointPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// ValidEndpointID: a lower-case UUID of 36 ASCII characters.
func ValidEndpointID(s string) bool { return endpointPattern.MatchString(s) }

// CheckTag refuses an empty or long tag, a NUL byte, and any tag that starts with the gate's own:
// no key-release REPORTDATA preimage may start with the gate's tag and its 0x00 separator
// (domain separation, chutes-tdx-gate spec/SPEC.md §4.1).
func CheckTag(tag string) error {
	if tag == "" || len(tag) > 128 {
		return errors.New("keyrel: the tag must be 1..128 bytes")
	}
	if strings.IndexByte(tag, 0) >= 0 {
		return errors.New("keyrel: the tag holds a NUL byte")
	}
	if strings.HasPrefix(tag, GateTag) {
		return errors.New("keyrel: the key-release tag must not start with the gate's /attest tag")
	}
	return nil
}

// ReportData is SHA-512(tag || 0x00 || nonce || exporter || endpointID).
func ReportData(tag string, nonce [32]byte, exporter [32]byte, endpointID string) [64]byte {
	h := sha512.New()
	h.Write([]byte(tag))
	h.Write([]byte{0})
	h.Write(nonce[:])
	h.Write(exporter[:])
	h.Write([]byte(endpointID))
	var out [64]byte
	copy(out[:], h.Sum(nil))
	return out
}

// Exporter is the connection's 32 bytes of exported keying material.
func Exporter(state tls.ConnectionState) ([32]byte, error) {
	var out [32]byte
	if state.Version != tls.VersionTLS13 {
		return out, errors.New("keyrel: TLS 1.3 only")
	}
	raw, err := state.ExportKeyingMaterial(ExporterLabel, nil, 32)
	if err != nil {
		return out, err
	}
	copy(out[:], raw)
	return out, nil
}

// Instance is the GCE instance the VM says it is (Google's provenance proves it).
type Instance struct {
	ProjectNumber string `json:"project_number"`
	Zone          string `json:"zone"`
	InstanceID    string `json:"instance_id"`
}

// NonceAnswer is GET /v1/nonce's answer.
type NonceAnswer struct {
	Nonce string `json:"nonce"`
}

// ReleaseRequest is POST /v1/release's body.
type ReleaseRequest struct {
	Nonce      string   `json:"nonce"`
	QuoteB64   string   `json:"quote_b64"`
	EndpointID string   `json:"endpoint_id"`
	Instance   Instance `json:"instance"`
}

// ReleaseAnswer is POST /v1/release's answer.
type ReleaseAnswer struct {
	KeyB64 string `json:"key_b64"`
}
