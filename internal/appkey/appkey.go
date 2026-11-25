// Package appkey derives the app partition's dm-crypt key from the key the owner's key service
// releases, and checks it before the partition is opened.
//
// The released key (the owner's app key, 64 bytes) is never the dm-crypt key itself. Each image
// build derives its own:
//
//	context  = HMAC-SHA256(released key, "chutes-tdx-image-app-context-v1" || 0x00 || SHA-256(app filesystem))
//	data key = HKDF-SHA256(released key, salt none, info "chutes-tdx-image-app-key-v1" || 0x00 || context), 64 bytes
//	kcv      = HMAC-SHA256(data key, "chutes-tdx-image-kcv-v1")
//
// Two builds with different app contents therefore use different dm-crypt keys, and no 16-byte
// block of one image's ciphertext can be compared with the same offset of another's, even under
// one owner key. The context depends on the app's plaintext (the image's own sha256 cannot be
// used: it covers the ciphertext, which depends on the key), and is keyed so that it says nothing
// about the plaintext to a reader of the root partition, where it is stored with the kcv in
// /etc/chutes-key-fetch.json. The kcv lets the VM tell, before cryptsetup, that the key service
// released another image's key. It is a PRF output of the data key, so it reveals nothing about
// the key.
package appkey

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
)

const (
	// KeySize is both the released key's and the dm-crypt key's size (aes-xts-plain64, 512 bits).
	KeySize = 64

	contextLabel = "chutes-tdx-image-app-context-v1"
	keyLabel     = "chutes-tdx-image-app-key-v1"
	kcvLabel     = "chutes-tdx-image-kcv-v1"
)

// Context is the image build's key context for an app filesystem whose SHA-256 is appDigest.
func Context(released []byte, appDigest [32]byte) [32]byte {
	m := hmac.New(sha256.New, released)
	m.Write([]byte(contextLabel))
	m.Write([]byte{0})
	m.Write(appDigest[:])
	var out [32]byte
	copy(out[:], m.Sum(nil))
	return out
}

// DataKey is the dm-crypt key for context.
func DataKey(released []byte, context [32]byte) ([]byte, error) {
	if len(released) != KeySize {
		return nil, errors.New("appkey: the released key is 64 bytes")
	}
	info := append(append([]byte(keyLabel), 0), context[:]...)
	return hkdf.Key(sha256.New, released, nil, string(info), KeySize)
}

// KCV is the data key's check value.
func KCV(dataKey []byte) [32]byte {
	m := hmac.New(sha256.New, dataKey)
	m.Write([]byte(kcvLabel))
	var out [32]byte
	copy(out[:], m.Sum(nil))
	return out
}

// Check reports whether dataKey has the check value kcv (constant time).
func Check(dataKey []byte, kcv [32]byte) bool {
	got := KCV(dataKey)
	return hmac.Equal(got[:], kcv[:])
}
