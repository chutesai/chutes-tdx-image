package appkey

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func released(b byte) []byte { return bytes.Repeat([]byte{b}, KeySize) }

// The derivation is fixed: these values pin it (a change is an incompatible image format).
// released = 64 bytes of 0x01, app filesystem = "app".
func TestFixedValues(t *testing.T) {
	ctx := Context(released(1), sha256.Sum256([]byte("app")))
	key, err := DataKey(released(1), ctx)
	if err != nil {
		t.Fatal(err)
	}
	kcv := KCV(key)
	if hex.EncodeToString(ctx[:]) != wantContext || hex.EncodeToString(kcv[:]) != wantKCV {
		t.Fatalf("context %x, kcv %x", ctx, kcv)
	}
}

// Two app contents under one released key give two data keys; one content under two released
// keys too; the kcv tells them apart.
func TestPerContentKeys(t *testing.T) {
	a, b := Context(released(1), sha256.Sum256([]byte("v1"))), Context(released(1), sha256.Sum256([]byte("v2")))
	if a == b {
		t.Fatal("two app contents share a context")
	}
	ka, _ := DataKey(released(1), a)
	kb, _ := DataKey(released(1), b)
	kc, _ := DataKey(released(2), a)
	if bytes.Equal(ka, kb) || bytes.Equal(ka, kc) || bytes.Equal(ka, released(1)) || len(ka) != KeySize {
		t.Fatal("data keys are not distinct")
	}
	if !Check(ka, KCV(ka)) || Check(kb, KCV(ka)) || Check(kc, KCV(ka)) {
		t.Fatal("the kcv does not tell keys apart")
	}
	if _, err := DataKey(released(1)[:32], a); err == nil {
		t.Fatal("a 32-byte released key was accepted")
	}
}

// Computed independently with Python's hmac and hashlib (HKDF written out per RFC 5869).
const (
	wantContext = "42604f679125ff2dc721394645f6c7ac15316b5ec62fe032f46e0c33dcb8a6cf"
	wantKCV     = "867a8dee5b43d726fa7c38869f23f98535cf44f74580803623118895e2c78c70"
)
