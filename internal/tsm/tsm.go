// Package tsm makes TDX quotes through the kernel's configfs-tsm interface
// (Documentation/ABI/testing/configfs-tsm-report), one at a time: mkdir; provider must be
// tdx_guest; generation; inblob; outblob; generation again (the first plus one, else one retry,
// then ErrBusy); rmdir. The same procedure as chutes-tdx-gate's pkg/attest.
package tsm

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// DefaultDir is the report directory.
const DefaultDir = "/sys/kernel/config/tsm/report"

// ErrBusy means another writer changed the entry while the quote was made, twice.
var ErrBusy = errors.New("tsm: configfs-tsm busy")

// Quoter makes a quote over 64 REPORTDATA bytes.
type Quoter interface {
	Quote(reportData [64]byte) ([]byte, error)
}

// Configfs is the configfs-tsm quoter.
type Configfs struct {
	Dir string
	mu  sync.Mutex
}

func read(path string) (string, error) {
	raw, err := os.ReadFile(path)
	return strings.TrimSpace(string(raw)), err
}

func generation(entry string) (uint64, error) {
	text, err := read(filepath.Join(entry, "generation"))
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(text, 10, 64)
}

var errMoved = errors.New("tsm: generation moved")

func (c *Configfs) once(reportData [64]byte) ([]byte, error) {
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return nil, err
	}
	entry := filepath.Join(c.Dir, "chutes-key-fetch-"+hex.EncodeToString(suffix[:]))
	if err := os.Mkdir(entry, 0o700); err != nil {
		return nil, err
	}
	defer os.Remove(entry)
	provider, err := read(filepath.Join(entry, "provider"))
	if err != nil {
		return nil, err
	}
	if provider != "tdx_guest" {
		return nil, fmt.Errorf("tsm: provider is %q, not tdx_guest", provider)
	}
	first, err := generation(entry)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(entry, "inblob"), os.O_WRONLY, 0)
	if err != nil {
		return nil, err
	}
	_, werr := f.Write(reportData[:])
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return nil, werr
	}
	quote, err := os.ReadFile(filepath.Join(entry, "outblob"))
	if err != nil {
		return nil, err
	}
	second, err := generation(entry)
	if err != nil {
		return nil, err
	}
	if second != first+1 {
		return nil, errMoved
	}
	return quote, nil
}

// Quote returns a quote over reportData.
func (c *Configfs) Quote(reportData [64]byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	q, err := c.once(reportData)
	if errors.Is(err, errMoved) {
		if q, err = c.once(reportData); errors.Is(err, errMoved) {
			return nil, ErrBusy
		}
	}
	return q, err
}
