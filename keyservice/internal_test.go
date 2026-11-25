package keyservice

import (
	"testing"
	"time"
)

// At most MaxNonces outstanding: a new connection beyond that gets none (503 nonce_busy); a
// connection asking again replaces its own.
func TestIssueCap(t *testing.T) {
	s := &Service{cfg: &Config{NonceTTLS: 60}, nonces: map[[32]byte]*issued{}, now: time.Now}
	var e [32]byte
	for i := 0; i < MaxNonces; i++ {
		e[0], e[1] = byte(i), byte(i>>8)
		if !s.issue(e, [32]byte{}) {
			t.Fatalf("nonce %d refused", i)
		}
	}
	e[0], e[1], e[2] = 0, 0, 1
	if s.issue(e, [32]byte{}) {
		t.Fatal("a nonce beyond MaxNonces was issued")
	}
	e[2] = 0
	if !s.issue(e, [32]byte{1}) || s.Outstanding() != MaxNonces {
		t.Fatal("a connection could not replace its own nonce")
	}
}
