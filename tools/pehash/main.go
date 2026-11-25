// Command pehash prints a PE image's Authenticode digests (SHA-256 and SHA-384, lower-case hex):
// what the firmware measures for an EFI application it loads (EV_EFI_BOOT_SERVICES_APPLICATION).
//
//	pehash out/uki.efi
package main

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"os"
	"sort"
)

// Authenticode hashes the image as the PE/COFF specification's Authenticode section says: the
// headers without the checksum and the certificate table entry, the sections in file order, then
// any data after them that is not the certificate table.
func Authenticode(data []byte, h hash.Hash) ([]byte, error) {
	if len(data) < 0x40 || string(data[:2]) != "MZ" {
		return nil, errors.New("not a PE image")
	}
	pe := int(binary.LittleEndian.Uint32(data[0x3c:]))
	if pe+24 > len(data) || string(data[pe:pe+4]) != "PE\x00\x00" {
		return nil, errors.New("no PE signature")
	}
	coff := pe + 4
	sections := int(binary.LittleEndian.Uint16(data[coff+2:]))
	optSize := int(binary.LittleEndian.Uint16(data[coff+16:]))
	opt := coff + 20
	if opt+optSize > len(data) || optSize < 2 {
		return nil, errors.New("truncated optional header")
	}
	var dirs int
	switch binary.LittleEndian.Uint16(data[opt:]) {
	case 0x20b: // PE32+
		dirs = opt + 112
	case 0x10b: // PE32
		dirs = opt + 96
	default:
		return nil, errors.New("unknown optional header magic")
	}
	checksum := opt + 64
	certEntry := dirs + 4*8
	if certEntry+8 > opt+optSize {
		return nil, errors.New("no certificate table entry")
	}
	headersEnd := int(binary.LittleEndian.Uint32(data[opt+60:]))
	certSize := int(binary.LittleEndian.Uint32(data[certEntry+4:]))
	if headersEnd > len(data) {
		return nil, errors.New("SizeOfHeaders beyond the file")
	}
	h.Write(data[:checksum])
	h.Write(data[checksum+4 : certEntry])
	h.Write(data[certEntry+8 : headersEnd])
	type span struct{ off, size int }
	var spans []span
	table := opt + optSize
	for i := 0; i < sections; i++ {
		s := table + 40*i
		if s+40 > len(data) {
			return nil, errors.New("truncated section table")
		}
		size := int(binary.LittleEndian.Uint32(data[s+16:]))
		off := int(binary.LittleEndian.Uint32(data[s+20:]))
		if size == 0 {
			continue
		}
		if off+size > len(data) {
			return nil, errors.New("section beyond the file")
		}
		spans = append(spans, span{off, size})
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].off < spans[j].off })
	end := headersEnd
	for _, s := range spans {
		h.Write(data[s.off : s.off+s.size])
		end = s.off + s.size
	}
	trailing := len(data) - end
	if certSize > 0 {
		trailing -= certSize
	}
	if trailing > 0 {
		h.Write(data[end : end+trailing])
	}
	return h.Sum(nil), nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: pehash FILE")
		os.Exit(2)
	}
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "pehash:", err)
		os.Exit(1)
	}
	for _, alg := range []struct {
		name string
		h    hash.Hash
	}{{"sha256", sha256.New()}, {"sha384", sha512.New384()}} {
		sum, err := Authenticode(data, alg.h)
		if err != nil {
			fmt.Fprintln(os.Stderr, "pehash:", err)
			os.Exit(1)
		}
		fmt.Printf("%s %s\n", alg.name, hex.EncodeToString(sum))
	}
}
