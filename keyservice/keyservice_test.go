package keyservice_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chutesai/chutes-tdx-image/internal/fakequote"
	"github.com/chutesai/chutes-tdx-image/internal/keyrel"
	"github.com/chutesai/chutes-tdx-image/internal/metadata"
	"github.com/chutesai/chutes-tdx-image/keyfetch"
	"github.com/chutesai/chutes-tdx-image/keyservice"
)

const (
	serverName = "keys.test.invalid"
	endpoint   = "6b1c0e7e-4d0b-4f2a-9a57-1f3d2c8b9e40"
	project    = "487213596071"
)

type pki struct {
	caPEM []byte
	cert  tls.Certificate
}

func newPKI(t *testing.T) pki {
	t.Helper()
	now := time.Now()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: serverName},
		DNSNames: []string{serverName}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	return pki{
		caPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		cert:  tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key},
	}
}

// verifier stands in for `chutes-tdx-measure verify-quote`: the binding row passes only when the
// quote's REPORTDATA is the one the service computed; the other rows answer as configured.
type verifier struct {
	mu        sync.Mutex
	rows      map[string]string
	calls     int
	instances []keyrel.Instance
	hook      func() // runs first, outside the lock (TestVerifiesBounded)
}

func (v *verifier) verify(_ context.Context, quote []byte, rd [64]byte, inst keyrel.Instance) (keyservice.Rows, error) {
	if v.hook != nil {
		v.hook()
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.calls++
	v.instances = append(v.instances, inst)
	var out keyservice.Rows
	out.Pass = true
	binding := "fail"
	if len(quote) >= 632 && bytes.Equal(quote[568:632], rd[:]) {
		binding = "pass"
	}
	for _, name := range keyservice.RequiredRows {
		status := v.rows[name]
		if status == "" {
			status = "pass"
		}
		if name == "binding" {
			status = binding
		}
		if status == "absent" {
			continue
		}
		if status != "pass" {
			out.Pass = false
		}
		out.Rows = append(out.Rows, struct {
			Row    string `json:"row"`
			Status string `json:"status"`
			Code   string `json:"code"`
		}{name, status, ""})
	}
	return out, nil
}

type fixture struct {
	key      []byte
	addr     string
	pki      pki
	verifier *verifier
	cfg      *keyservice.Config
	svc      *keyservice.Service
	clock    atomic.Int64 // the service's clock (UnixNano); 0: time.Now
}

// nonceOnly asks for a nonce on a new connection and closes it without using it.
func (f *fixture) nonceOnly(t *testing.T) {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(f.pki.caPEM)
	c, err := tls.Dial("tcp", f.addr, &tls.Config{ServerName: serverName, RootCAs: pool, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	req, _ := http.NewRequest("GET", "https://"+serverName+"/v1/nonce", nil)
	_ = req.Write(c)
	resp, err := http.ReadResponse(bufio.NewReader(c), req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("nonce: %v", err)
	}
	resp.Body.Close()
}

func start(t *testing.T, endpoints ...string) *fixture {
	t.Helper()
	if len(endpoints) == 0 {
		endpoints = []string{endpoint}
	}
	f := &fixture{key: make([]byte, 64), pki: newPKI(t), verifier: &verifier{rows: map[string]string{}}}
	_, _ = rand.Read(f.key)
	f.cfg = &keyservice.Config{Schema: keyservice.ConfigSchema, Tag: keyrel.DefaultTag, Endpoints: endpoints, NonceTTLS: 60,
		Verify: keyservice.VerifyConfig{GCEProject: project}}
	svc, err := keyservice.New(f.cfg, f.key, f.verifier.verify, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	svc.SetClock(func() time.Time {
		if n := f.clock.Load(); n != 0 {
			return time.Unix(0, n)
		}
		return time.Now()
	})
	f.svc = svc
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{f.pki.cert}, NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: svc}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	f.addr = ln.Addr().String()
	return f
}

func (f *fixture) fetcher(quoter interface {
	Quote([64]byte) ([]byte, error)
}, id metadata.Identity) *keyfetch.Fetcher {
	return &keyfetch.Fetcher{
		Config:    &keyfetch.Config{ServerName: serverName, CAPEM: string(f.pki.caPEM), Tag: keyrel.DefaultTag},
		Quoter:    quoter,
		Identity:  id,
		RelayAddr: f.addr,
	}
}

var vm = metadata.Identity{EndpointID: endpoint, InstanceID: "5813945712345678901", ProjectNumber: project, Zone: "us-central1-a"}

func TestKeyWindowRoundTrip(t *testing.T) {
	f := start(t)
	q := &fakequote.Quoter{}
	key, err := f.fetcher(q, vm).FetchOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key, f.key) {
		t.Fatal("another key was released")
	}
	if len(f.verifier.instances) != 1 || f.verifier.instances[0] != (keyrel.Instance{ProjectNumber: project, Zone: "us-central1-a", InstanceID: vm.InstanceID}) {
		t.Fatalf("the verifier got %+v", f.verifier.instances)
	}
	if len(q.Seen) != 1 {
		t.Fatal("one quote expected")
	}
}

// REPORTDATA is SHA-512(tag || 0x00 || nonce || exporter || endpoint_id). (TestKeyWindowRoundTrip
// proves the fetcher computes it with its endpoint id: the service's binding uses the request's.)
func TestReportDataRule(t *testing.T) {
	var n, e [32]byte
	_, _ = rand.Read(n[:])
	_, _ = rand.Read(e[:])
	a := keyrel.ReportData(keyrel.DefaultTag, n, e, endpoint)
	b := keyrel.ReportData(keyrel.DefaultTag, n, e, "00000000-0000-4000-8000-000000000000")
	if a == b {
		t.Fatal("the endpoint id is not in REPORTDATA")
	}
	h := sha512.New()
	h.Write([]byte(keyrel.DefaultTag + "\x00"))
	h.Write(n[:])
	h.Write(e[:])
	h.Write([]byte(endpoint))
	if !bytes.Equal(h.Sum(nil), a[:]) {
		t.Fatal("REPORTDATA is not SHA-512(tag || 0x00 || nonce || exporter || endpoint_id)")
	}
	if keyrel.CheckTag(keyrel.GateTag) == nil {
		t.Fatal("the gate's /attest tag was accepted as a key-release tag")
	}
}

// A VM of another endpoint (a copy of the image under someone else's endpoint) gets no key.
func TestEndpointNotListed(t *testing.T) {
	f := start(t, "0d8f4a52-1c3e-4b7a-9f60-2e5d7c9a1b34")
	if _, err := f.fetcher(&fakequote.Quoter{}, vm).FetchOnce(context.Background()); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("released to an endpoint not on the list: %v", err)
	}
	if f.verifier.calls != 0 {
		t.Fatal("the quote was verified for an endpoint not on the list")
	}
}

// Provenance is mandatory: a failing or missing provider_root row refuses the key.
func TestProvenanceRequired(t *testing.T) {
	for _, status := range []string{"fail", "absent", "not_checked"} {
		f := start(t)
		f.verifier.rows["provider_root"] = status
		if _, err := f.fetcher(&fakequote.Quoter{}, vm).FetchOnce(context.Background()); err == nil {
			t.Fatalf("released with provider_root %s", status)
		}
	}
	for _, row := range []string{"quote", "platform", "measurements"} {
		f := start(t)
		f.verifier.rows[row] = "fail"
		if _, err := f.fetcher(&fakequote.Quoter{}, vm).FetchOnce(context.Background()); err == nil {
			t.Fatalf("released with %s failing", row)
		}
	}
}

// A quote over other REPORTDATA than the service computes is refused (the binding).
func TestQuoteOverOtherReportDataRefused(t *testing.T) {
	f := start(t)
	if _, err := f.fetcher(&swapQuoter{}, vm).FetchOnce(context.Background()); err == nil {
		t.Fatal("a quote over other REPORTDATA released the key")
	}
}

// swapQuoter quotes REPORTDATA other than it was asked for.
type swapQuoter struct{}

func (s *swapQuoter) Quote(rd [64]byte) ([]byte, error) {
	var other [64]byte
	copy(other[:], rd[:])
	other[0] ^= 0xff
	return fakequote.Quote(other), nil
}

func TestProjectPinned(t *testing.T) {
	f := start(t)
	other := vm
	other.ProjectNumber = "111111111111"
	if _, err := f.fetcher(&fakequote.Quoter{}, other).FetchOnce(context.Background()); err == nil {
		t.Fatal("released to a VM of another project")
	}
}

// Raw protocol checks: a nonce is single-use and bound to its connection.
func TestNonceRules(t *testing.T) {
	f := start(t)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(f.pki.caPEM)
	dial := func() (*tls.Conn, *bufio.Reader) {
		c, err := tls.Dial("tcp", f.addr, &tls.Config{ServerName: serverName, RootCAs: pool, MinVersion: tls.VersionTLS13})
		if err != nil {
			t.Fatal(err)
		}
		return c, bufio.NewReader(c)
	}
	do := func(c *tls.Conn, br *bufio.Reader, method, path string, body []byte) (int, []byte) {
		req, _ := http.NewRequest(method, "https://"+serverName+path, bytes.NewReader(body))
		if err := req.Write(c); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(br, req)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.StatusCode, raw
	}
	release := func(c *tls.Conn, br *bufio.Reader, nonce string) int {
		exp, _ := keyrel.Exporter(c.ConnectionState())
		var n [32]byte
		_, _ = hex.Decode(n[:], []byte(nonce))
		rd := keyrel.ReportData(keyrel.DefaultTag, n, exp, endpoint)
		body, _ := json.Marshal(keyrel.ReleaseRequest{Nonce: nonce, QuoteB64: base64.StdEncoding.EncodeToString(fakequote.Quote(rd)),
			EndpointID: endpoint, Instance: keyrel.Instance{ProjectNumber: project, Zone: "us-central1-a", InstanceID: "5813945712345678901"}})
		status, _ := do(c, br, "POST", "/v1/release", body)
		return status
	}
	c1, br1 := dial()
	defer c1.Close()
	_, raw := do(c1, br1, "GET", "/v1/nonce", nil)
	var na keyrel.NonceAnswer
	_ = json.Unmarshal(raw, &na)
	// The nonce on another connection: refused.
	c2, br2 := dial()
	defer c2.Close()
	if status := release(c2, br2, na.Nonce); status != 403 {
		t.Fatalf("a nonce of another connection: %d", status)
	}
	// On its own connection: once.
	if status := release(c1, br1, na.Nonce); status != 200 {
		t.Fatalf("the right nonce: %d", status)
	}
	if status := release(c1, br1, na.Nonce); status != 403 {
		t.Fatalf("the nonce again: %d", status)
	}
}

// The fetcher trusts only its pinned CA: a key service with a certificate from another CA (a
// relay that terminates TLS, say) gets nothing.
func TestFetchRefusesAnotherCA(t *testing.T) {
	f := start(t)
	other := newPKI(t)
	fetch := f.fetcher(&fakequote.Quoter{}, vm)
	fetch.Config.CAPEM = string(other.caPEM)
	if _, err := fetch.FetchOnce(context.Background()); err == nil {
		t.Fatal("a key service outside the pinned CA was trusted")
	}
	if f.verifier.calls != 0 {
		t.Fatal("a quote was sent to a server outside the pinned CA")
	}
}

// A nonce is deleted when it is used (pass or fail); expired ones go when the next is issued.
func TestNoncesDoNotAccumulate(t *testing.T) {
	f := start(t)
	if _, err := f.fetcher(&fakequote.Quoter{}, vm).FetchOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := f.svc.Outstanding(); n != 0 {
		t.Fatalf("%d nonces kept after use", n)
	}
	f.verifier.rows["quote"] = "fail"
	_, _ = f.fetcher(&fakequote.Quoter{}, vm).FetchOnce(context.Background())
	if n := f.svc.Outstanding(); n != 0 {
		t.Fatalf("%d nonces kept after a refusal", n)
	}
	f.verifier.rows["quote"] = "pass"
	// Nonces asked for and never used expire: issuing the next one drops them.
	for i := 0; i < 3; i++ {
		f.nonceOnly(t)
	}
	if n := f.svc.Outstanding(); n != 3 {
		t.Fatalf("%d outstanding, want 3", n)
	}
	f.clock.Store(time.Now().Add(61 * time.Second).UnixNano())
	f.nonceOnly(t)
	if n := f.svc.Outstanding(); n != 1 {
		t.Fatalf("%d outstanding after the others expired, want 1", n)
	}
}

// At most MaxVerifies verify-quote runs at once; the others wait for a slot.
func TestVerifiesBounded(t *testing.T) {
	f := start(t)
	release := make(chan struct{})
	var running, most int32
	var mu sync.Mutex
	f.verifier.hook = func() {
		mu.Lock()
		running++
		if running > most {
			most = running
		}
		mu.Unlock()
		<-release
		mu.Lock()
		running--
		mu.Unlock()
	}
	var wg sync.WaitGroup
	for i := 0; i < keyservice.MaxVerifies+3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = f.fetcher(&fakequote.Quoter{}, vm).FetchOnce(context.Background())
		}()
	}
	time.Sleep(300 * time.Millisecond)
	close(release)
	wg.Wait()
	if most != keyservice.MaxVerifies || f.verifier.calls != keyservice.MaxVerifies+3 {
		t.Fatalf("at most %d at once (want %d), %d calls", most, keyservice.MaxVerifies, f.verifier.calls)
	}
}
