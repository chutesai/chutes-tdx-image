package main

import (
	"crypto/sha512"
	"encoding/binary"
	"testing"
)

// A minimal PE32+ with two sections: the digest covers the headers without the checksum and the
// certificate-table entry, then the sections in file order, then trailing data.
func TestAuthenticode(t *testing.T) {
	pe := make([]byte, 0x400)
	copy(pe, "MZ")
	binary.LittleEndian.PutUint32(pe[0x3c:], 0x40)
	copy(pe[0x40:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(pe[0x46:], 2)   // sections
	binary.LittleEndian.PutUint16(pe[0x54:], 240) // optional header size
	opt := 0x58
	binary.LittleEndian.PutUint16(pe[opt:], 0x20b)
	binary.LittleEndian.PutUint32(pe[opt+60:], 0x400)
	binary.LittleEndian.PutUint32(pe[opt+64:], 0xdeadbeef) // checksum
	binary.LittleEndian.PutUint32(pe[opt+108:], 16)
	table := opt + 240
	// section B first in the table but later in the file: hashed in file order.
	binary.LittleEndian.PutUint32(pe[table+16:], 0x200)
	binary.LittleEndian.PutUint32(pe[table+20:], 0x600)
	binary.LittleEndian.PutUint32(pe[table+40+16:], 0x200)
	binary.LittleEndian.PutUint32(pe[table+40+20:], 0x400)
	a := make([]byte, 0x200)
	b := make([]byte, 0x200)
	for i := range a {
		a[i], b[i] = 'a', 'b'
	}
	pe = append(append(append(pe, a...), b...), []byte("trailer")...)
	got, err := Authenticode(pe, sha512.New384())
	if err != nil {
		t.Fatal(err)
	}
	h := sha512.New384()
	h.Write(pe[:opt+64])
	h.Write(pe[opt+68 : opt+112+32])
	h.Write(pe[opt+112+40 : 0x400])
	h.Write(a)
	h.Write(b)
	h.Write([]byte("trailer"))
	if string(got) != string(h.Sum(nil)) {
		t.Fatal("Authenticode digest")
	}
	pe2 := append([]byte(nil), pe...)
	binary.LittleEndian.PutUint32(pe2[opt+64:], 1) // another checksum: the same digest
	got2, _ := Authenticode(pe2, sha512.New384())
	if string(got2) != string(got) {
		t.Fatal("the checksum is not excluded")
	}
	pe2[0x400] ^= 1
	got3, _ := Authenticode(pe2, sha512.New384())
	if string(got3) == string(got) {
		t.Fatal("a section byte is not covered")
	}
}
