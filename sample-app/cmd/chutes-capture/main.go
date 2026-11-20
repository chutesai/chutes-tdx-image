// Command chutes-capture runs only in the capture variant of the sample image. It prints the
// platform's measurements on the serial console, where Chutes reads them for its platform data,
// and does nothing else.
//
// It reads the metadata attribute chutes-capture-nonce (64 hex), makes a quote over
// SHA-512("chutes-tdx-capture-v1" || 0x00 || nonce), reads the CCEL event log, and writes
//
//	CHUTES-CAPTURE-V1 <base64 of {"quote": <base64>, "ccel": <base64>}>
//
// to the serial console every 30 s (so a late reader still sees it). The capture variant has no
// key fetch, no app partition and no gate.
package main

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"log"
	"os"
	"regexp"
	"time"

	"github.com/chutesai/chutes-tdx-image/internal/metadata"
	"github.com/chutesai/chutes-tdx-image/internal/tsm"
)

// Tag is the capture's REPORTDATA tag (never the gate's or the key release's).
const Tag = "chutes-tdx-capture-v1"

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Line is the serial line for a quote and an event log.
func Line(quote, ccel []byte) string {
	doc, _ := json.Marshal(map[string]string{
		"quote": base64.StdEncoding.EncodeToString(quote),
		"ccel":  base64.StdEncoding.EncodeToString(ccel),
	})
	return "CHUTES-CAPTURE-V1 " + base64.StdEncoding.EncodeToString(doc) + "\n"
}

// ReportData is SHA-512(Tag || 0x00 || nonce).
func ReportData(nonce [32]byte) [64]byte {
	h := sha512.New()
	h.Write([]byte(Tag))
	h.Write([]byte{0})
	h.Write(nonce[:])
	var out [64]byte
	copy(out[:], h.Sum(nil))
	return out
}

func main() {
	console := flag.String("console", "/dev/ttyS0", "where the line is written")
	ccelPath := flag.String("ccel", "/sys/firmware/acpi/tables/data/CCEL", "the CCEL event log")
	flag.Parse()
	md := metadata.New(metadata.Base)
	var nonceHex string
	for {
		v, err := md.Get(context.Background(), "instance/attributes/chutes-capture-nonce")
		if err == nil && hex64.MatchString(v) {
			nonceHex = v
			break
		}
		log.Printf("waiting for chutes-capture-nonce: %v", err)
		time.Sleep(2 * time.Second)
	}
	var nonce [32]byte
	_, _ = hex.Decode(nonce[:], []byte(nonceHex))
	quote, err := (&tsm.Configfs{Dir: tsm.DefaultDir}).Quote(ReportData(nonce))
	if err != nil {
		log.Fatalf("quote: %v", err)
	}
	ccel, err := os.ReadFile(*ccelPath)
	if err != nil {
		log.Fatalf("ccel: %v", err)
	}
	line := Line(quote, ccel)
	for {
		if f, err := os.OpenFile(*console, os.O_WRONLY, 0); err == nil {
			_, _ = f.WriteString(line)
			f.Close()
		}
		time.Sleep(30 * time.Second)
	}
}
