// Command appseal encrypts the app filesystem image for the app partition, deterministically, as
// plain dm-crypt aes-xts-plain64 with a 512-bit key reads it:
//
//	appseal --key app.key --in app.erofs --out app.ct --meta app.meta.json
//	appseal --key app.key --context HEX --data-key     (the data key, raw, on stdout: a pipe only)
//
// app.key is the owner's app key, the one the key service releases. The partition is encrypted
// under this build's own data key (internal/appkey): the context is keyed on the app
// filesystem's SHA-256, so another app content gets another key; --meta writes the context and
// the data key's check value (kcv) for /etc/chutes-key-fetch.json.
//
// The input is zero-padded to a multiple of 4096 bytes (dm-verity's block), then each 512-byte
// sector n is encrypted with XTS-AES-256 under key[0:32] (data) and key[32:64] (tweak), tweak = n
// as a 64-bit little-endian number: exactly what `cryptsetup open --type plain --cipher
// aes-xts-plain64 --key-size 512` decrypts. The same key and input give the same bytes, so the
// image build stays reproducible (LUKS2 would add random salts to the header). No key is printed
// except by --data-key, on purpose, to a pipe.
package main

import (
	"crypto/aes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"golang.org/x/crypto/xts"

	"github.com/chutesai/chutes-tdx-image/internal/appkey"
)

const (
	sector = 512
	block  = 4096
)

// Seal encrypts (or decrypts) data in place, sector by sector.
func Seal(key, data []byte, decrypt bool) error {
	if len(key) != 64 {
		return errors.New("appseal: the key is 64 bytes")
	}
	if len(data)%sector != 0 {
		return errors.New("appseal: the data is not a whole number of sectors")
	}
	c, err := xts.NewCipher(aes.NewCipher, key)
	if err != nil {
		return err
	}
	for n := 0; n*sector < len(data); n++ {
		s := data[n*sector : (n+1)*sector]
		if decrypt {
			c.Decrypt(s, s, uint64(n))
		} else {
			c.Encrypt(s, s, uint64(n))
		}
	}
	return nil
}

// Meta is what the VM needs to derive and check the data key: written to --meta.
type Meta struct {
	AppContext string `json:"app_context"`
	AppKCV     string `json:"app_kcv"`
}

// SealImage pads data to whole 4096-byte blocks and encrypts it under the build's data key,
// returning the meta.
func SealImage(released, data []byte) ([]byte, Meta, error) {
	if pad := (block - len(data)%block) % block; pad != 0 {
		data = append(data, make([]byte, pad)...)
	}
	context := appkey.Context(released, sha256.Sum256(data))
	key, err := appkey.DataKey(released, context)
	if err != nil {
		return nil, Meta{}, err
	}
	defer clear(key)
	kcv := appkey.KCV(key)
	if err := Seal(key, data, false); err != nil {
		return nil, Meta{}, err
	}
	return data, Meta{AppContext: hex.EncodeToString(context[:]), AppKCV: hex.EncodeToString(kcv[:])}, nil
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "appseal:", err)
	os.Exit(1)
}

func main() {
	keyPath := flag.String("key", "", "the owner's 64-byte app key file")
	in := flag.String("in", "", "the app filesystem image")
	out := flag.String("out", "", "the encrypted image")
	meta := flag.String("meta", "", "where to write {app_context, app_kcv}")
	contextHex := flag.String("context", "", "with --data-key: the build's app_context")
	dataKey := flag.Bool("data-key", false, "print the data key for --context, raw, on stdout (a pipe)")
	flag.Parse()
	released, err := os.ReadFile(*keyPath)
	if err == nil && len(released) != appkey.KeySize {
		err = errors.New("the key file must hold exactly 64 bytes")
	}
	if err != nil {
		fail(err)
	}
	defer clear(released)
	if *dataKey {
		var context [32]byte
		if raw, err := hex.DecodeString(*contextHex); err != nil || len(raw) != 32 {
			fail(errors.New("--context must be 64 hex characters"))
		} else {
			copy(context[:], raw)
		}
		key, err := appkey.DataKey(released, context)
		if err != nil {
			fail(err)
		}
		_, err = os.Stdout.Write(key)
		clear(key)
		if err != nil {
			fail(err)
		}
		return
	}
	data, err := os.ReadFile(*in)
	if err != nil {
		fail(err)
	}
	sealed, m, err := SealImage(released, data)
	if err != nil {
		fail(err)
	}
	if err := os.WriteFile(*out, sealed, 0o644); err != nil {
		fail(err)
	}
	raw, _ := json.Marshal(m)
	if err := os.WriteFile(*meta, append(raw, '\n'), 0o644); err != nil {
		fail(err)
	}
}
