// Package keyfetch is the VM's side of the key window: it dials the key
// relay named by the metadata attribute chutes-key-relay, runs TLS 1.3 end to end to the owner's
// key service (ServerName and a pinned CA from /etc/chutes-key-fetch.json), and asks for the key
// with a quote over the reference REPORTDATA (keyrel.ReportData: the tag, the service's nonce, the
// connection's exporter and this VM's endpoint id). It retries 1 s doubling to 30 s until it has
// the key, which it hands to the caller only (never to disk, never to a log). Each attempt has
// AttemptTimeout (180 s: longer than the reference service's verify-quote limit of 120 s, so a
// slow verification is waited for rather than abandoned); every attempt is one of the key window's
// four connections, so an abandoned attempt costs one.
package keyfetch

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"time"

	"github.com/chutesai/chutes-tdx-image/internal/appkey"
	"github.com/chutesai/chutes-tdx-image/internal/keyrel"
	"github.com/chutesai/chutes-tdx-image/internal/metadata"
	"github.com/chutesai/chutes-tdx-image/internal/tsm"
)

// Config is /etc/chutes-key-fetch.json: {"server_name", "ca_pem", "tag", "app_context",
// "app_kcv"}. The last two are the image build's (internal/appkey): the context the app
// partition's data key is derived with, and that key's check value.
type Config struct {
	ServerName string `json:"server_name"`
	CAPEM      string `json:"ca_pem"`
	Tag        string `json:"tag"`
	AppContext string `json:"app_context"`
	AppKCV     string `json:"app_kcv"`
}

// AttemptTimeout bounds one attempt (one connection of the key window).
const AttemptTimeout = 180 * time.Second

// LoadConfig reads and checks the closed configuration.
func LoadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(raw, &keys); err != nil || len(keys) != 5 {
		return nil, errors.New("keyfetch: the configuration is exactly {server_name, ca_pem, tag, app_context, app_kcv}")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var c Config
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("keyfetch: configuration: %w", err)
	}
	if c.ServerName == "" || c.CAPEM == "" {
		return nil, errors.New("keyfetch: server_name and ca_pem are required")
	}
	if err := keyrel.CheckTag(c.Tag); err != nil {
		return nil, err
	}
	if !x509.NewCertPool().AppendCertsFromPEM([]byte(c.CAPEM)) {
		return nil, errors.New("keyfetch: ca_pem holds no certificate")
	}
	if !hex64.MatchString(c.AppContext) || !hex64.MatchString(c.AppKCV) {
		return nil, errors.New("keyfetch: app_context and app_kcv are 64 lower-case hex characters")
	}
	return &c, nil
}

// DataKey derives the app partition's dm-crypt key from the released key and checks it against
// the image's check value: an error means the key service released another image's key (or
// another owner key), which no retry fixes.
func (c *Config) DataKey(released []byte) ([]byte, error) {
	var context, kcv [32]byte
	if _, err := hex.Decode(context[:], []byte(c.AppContext)); err != nil {
		return nil, err
	}
	if _, err := hex.Decode(kcv[:], []byte(c.AppKCV)); err != nil {
		return nil, err
	}
	key, err := appkey.DataKey(released, context)
	if err != nil {
		return nil, err
	}
	if !appkey.Check(key, kcv) {
		clear(key)
		return nil, ErrKeyCheck
	}
	return key, nil
}

// ErrKeyCheck is a released key that does not belong to this image.
var ErrKeyCheck = errors.New("key_check_failed: the released key does not open this image's app partition (the key service holds another image's or another owner's key)")

// Fetcher fetches the key once the VM knows its identity and the relay's address.
type Fetcher struct {
	Config    *Config
	Quoter    tsm.Quoter
	Identity  metadata.Identity
	RelayAddr string
	// Dial connects to the relay (default: TCP with a 10 s timeout).
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// Logf records progress; never the key.
	Logf func(format string, args ...any)
}

func (f *Fetcher) logf(format string, args ...any) {
	if f.Logf != nil {
		f.Logf(format, args...)
	}
}

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

func roundTrip(conn *tls.Conn, br *bufio.Reader, req *http.Request) ([]byte, error) {
	if err := req.Write(conn); err != nil {
		return nil, err
	}
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("key service answered %d", resp.StatusCode)
	}
	return body, nil
}

// FetchOnce runs one attempt over one TLS connection.
func (f *Fetcher) FetchOnce(ctx context.Context) ([]byte, error) {
	dial := f.Dial
	if dial == nil {
		dial = (&net.Dialer{Timeout: 10 * time.Second}).DialContext
	}
	raw, err := dial(ctx, "tcp", f.RelayAddr)
	if err != nil {
		return nil, err
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(AttemptTimeout))
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(f.Config.CAPEM))
	conn := tls.Client(raw, &tls.Config{
		ServerName: f.Config.ServerName,
		RootCAs:    pool,
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"http/1.1"},
	})
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	exporter, err := keyrel.Exporter(conn.ConnectionState())
	if err != nil {
		return nil, err
	}
	br := bufio.NewReader(conn)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+f.Config.ServerName+"/v1/nonce", nil)
	body, err := roundTrip(conn, br, req)
	if err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	var na keyrel.NonceAnswer
	if err := json.Unmarshal(body, &na); err != nil || !hex64.MatchString(na.Nonce) {
		return nil, errors.New("nonce: malformed answer")
	}
	var nonce [32]byte
	_, _ = hex.Decode(nonce[:], []byte(na.Nonce))
	rd := keyrel.ReportData(f.Config.Tag, nonce, exporter, f.Identity.EndpointID)
	quote, err := f.Quoter.Quote(rd)
	if err != nil {
		return nil, fmt.Errorf("quote: %w", err)
	}
	payload, _ := json.Marshal(keyrel.ReleaseRequest{
		Nonce:      na.Nonce,
		QuoteB64:   base64.StdEncoding.EncodeToString(quote),
		EndpointID: f.Identity.EndpointID,
		Instance: keyrel.Instance{
			ProjectNumber: f.Identity.ProjectNumber, Zone: f.Identity.Zone, InstanceID: f.Identity.InstanceID,
		},
	})
	req, _ = http.NewRequestWithContext(ctx, http.MethodPost, "https://"+f.Config.ServerName+"/v1/release", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	body, err = roundTrip(conn, br, req)
	if err != nil {
		return nil, fmt.Errorf("release: %w", err)
	}
	var ra keyrel.ReleaseAnswer
	if err := json.Unmarshal(body, &ra); err != nil {
		return nil, errors.New("release: malformed answer")
	}
	key, err := base64.StdEncoding.DecodeString(ra.KeyB64)
	if err != nil || len(key) != keyrel.KeySize {
		return nil, errors.New("release: the key is not 64 bytes")
	}
	return key, nil
}

// Fetch retries every 1 s, doubling to 30 s, until it has the key: the window opens a few
// seconds after the VM starts, so the first attempts can be refused.
func (f *Fetcher) Fetch(ctx context.Context) ([]byte, error) {
	delay := time.Second
	for attempt := 1; ; attempt++ {
		key, err := f.FetchOnce(ctx)
		if err == nil {
			f.logf("key fetched (attempt %d)", attempt)
			return key, nil
		}
		f.logf("attempt %d failed: %v; retrying in %s", attempt, err, delay)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(delay):
		}
		delay = min(delay*2, 30*time.Second)
	}
}
