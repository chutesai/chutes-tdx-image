// Package fakequote makes UNSIGNED synthetic TDX v4 quotes carrying a given REPORTDATA (tests
// only: no verifier accepts them).
package fakequote

import (
	"encoding/binary"
	"sync"
)

// Quote is a 640-byte v4 quote with reportData at absolute offset 568.
func Quote(reportData [64]byte) []byte {
	q := make([]byte, 640)
	binary.LittleEndian.PutUint16(q[0:2], 4)
	binary.LittleEndian.PutUint16(q[2:4], 2)
	binary.LittleEndian.PutUint32(q[4:8], 0x81)
	copy(q[568:632], reportData[:])
	binary.LittleEndian.PutUint32(q[632:636], 4)
	return q
}

// Quoter records the REPORTDATA it was asked for.
type Quoter struct {
	mu   sync.Mutex
	Seen [][64]byte
}

func (f *Quoter) Quote(rd [64]byte) ([]byte, error) {
	f.mu.Lock()
	f.Seen = append(f.Seen, rd)
	f.mu.Unlock()
	return Quote(rd), nil
}
