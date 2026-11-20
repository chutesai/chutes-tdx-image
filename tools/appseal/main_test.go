package main

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/xts"

	"github.com/chutesai/chutes-tdx-image/internal/appkey"
)

// IEEE 1619-2007 XTS-AES-256 vector 10 (data unit sequence number 0xff, a 512-byte data unit): the
// tweak is the sector number, little-endian, as dm-crypt's plain64 IV.
func TestXTSVector(t *testing.T) {
	key, _ := hex.DecodeString("2718281828459045235360287471352662497757247093699959574966967627" +
		"3141592653589793238462643383279502884197169399375105820974944592")
	pt := make([]byte, 512)
	for i := range pt {
		pt[i] = byte(i)
	}
	want, _ := hex.DecodeString("1c3b3a102f770386e4836c99e370cf9bea00803f5e482357a4ae12d414a3e63b5d31e276f8fe4a8d66b317f9ac683f44680a86ac35adfc3345befecb4bb188fd")
	c, _ := xts.NewCipher(aes.NewCipher, key)
	ct := make([]byte, 512)
	c.Encrypt(ct, pt, 0xff)
	if !bytes.Equal(ct[:64], want) {
		t.Fatalf("XTS vector 10: %x", ct[:64])
	}
}

func TestSealRoundTrip(t *testing.T) {
	key := make([]byte, 64)
	_, _ = rand.Read(key)
	data := make([]byte, 8192)
	_, _ = rand.Read(data)
	ct := append([]byte(nil), data...)
	if err := Seal(key, ct, false); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(ct[:512], data[:512]) || bytes.Equal(ct[:512], ct[512:1024]) {
		t.Fatal("not encrypted per sector")
	}
	again := append([]byte(nil), data...)
	_ = Seal(key, again, false)
	if !bytes.Equal(again, ct) {
		t.Fatal("not deterministic")
	}
	if err := Seal(key, ct, true); err != nil || !bytes.Equal(ct, data) {
		t.Fatal("round trip")
	}
	// Identical sectors encrypt differently: the tweak is each sector's number.
	zeros := make([]byte, 2048)
	_ = Seal(key, zeros, false)
	if bytes.Equal(zeros[:512], zeros[512:1024]) {
		t.Fatal("the tweak is not the sector number")
	}
	if Seal(key[:32], ct, false) == nil || Seal(key, ct[:100], false) == nil {
		t.Fatal("bad sizes accepted")
	}
}

// The image is sealed under the build's data key, never under the released key, and the meta
// lets the key be derived again and checked.
func TestSealImageUsesTheDataKey(t *testing.T) {
	released := bytes.Repeat([]byte{9}, 64)
	data := bytes.Repeat([]byte("app filesystem "), 600) // not a whole block: padded
	sealed, m, err := SealImage(released, append([]byte(nil), data...))
	if err != nil || len(sealed)%4096 != 0 {
		t.Fatal(err)
	}
	padded := append(append([]byte(nil), data...), make([]byte, len(sealed)-len(data))...)
	underReleased := append([]byte(nil), padded...)
	_ = Seal(released, underReleased, false)
	if bytes.Equal(sealed, underReleased) {
		t.Fatal("sealed under the released key itself")
	}
	ctxRaw, _ := hex.DecodeString(m.AppContext)
	var ctx [32]byte
	copy(ctx[:], ctxRaw)
	key, _ := appkey.DataKey(released, ctx)
	kcvRaw, _ := hex.DecodeString(m.AppKCV)
	var kcv [32]byte
	copy(kcv[:], kcvRaw)
	if !appkey.Check(key, kcv) {
		t.Fatal("the meta's kcv does not check the data key")
	}
	opened := append([]byte(nil), sealed...)
	if err := Seal(key, opened, true); err != nil || !bytes.Equal(opened, padded) {
		t.Fatal("the data key does not open the image")
	}
	// Another app content under the same released key: another key, so no block compares.
	other, m2, _ := SealImage(released, append([]byte("v2 "), data[3:]...))
	if m2.AppContext == m.AppContext || bytes.Equal(other[4096:8192], sealed[4096:8192]) {
		t.Fatal("two app contents share a data key")
	}
}
