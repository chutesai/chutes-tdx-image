// Package metadata reads the GCE metadata server at 169.254.169.254 (metadata.google.internal
// does not resolve in a Chutes customer VM): no proxy, no redirect, Metadata-Flavor: Google both
// ways, small answers only.
package metadata

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Base is the metadata server's v1 root.
const Base = "http://169.254.169.254/computeMetadata/v1/"

// Client reads metadata values.
type Client struct {
	Base string
	http *http.Client
}

// New returns a client for base (Base in a VM).
func New(base string) *Client {
	return &Client{Base: base, http: &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy:             nil,
			DialContext:       (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
			DisableKeepAlives: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// Get reads one value (trimmed), at most 4 KiB.
func (c *Client) Get(ctx context.Context, path string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Base+path, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Metadata-Flavor") != "Google" {
		return "", errors.New("metadata: not a 200 from the metadata server")
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4097))
	if err != nil || len(raw) > 4096 {
		return "", errors.New("metadata: answer too long")
	}
	return strings.TrimSpace(string(raw)), nil
}

var (
	zonePattern  = regexp.MustCompile(`^projects/([1-9][0-9]{0,19})/zones/([a-z]+(-[a-z]+)+[0-9]+-[a-z])$`)
	gceIDPattern = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)
	relayPattern = regexp.MustCompile(`^([0-9]{1,3}(\.[0-9]{1,3}){3}):([0-9]{1,5})$`)
)

// Identity is what the VM reads about itself.
type Identity struct {
	EndpointID    string
	InstanceID    string
	ProjectNumber string
	Zone          string
}

// ReadIdentity reads chutes-endpoint-id, instance/id and instance/zone (projects/N/zones/Z).
func (c *Client) ReadIdentity(ctx context.Context) (Identity, error) {
	var id Identity
	var err error
	if id.EndpointID, err = c.Get(ctx, "instance/attributes/chutes-endpoint-id"); err != nil {
		return id, err
	}
	if id.InstanceID, err = c.Get(ctx, "instance/id"); err != nil {
		return id, err
	}
	zone, err := c.Get(ctx, "instance/zone")
	if err != nil {
		return id, err
	}
	m := zonePattern.FindStringSubmatch(zone)
	if m == nil || !gceIDPattern.MatchString(id.InstanceID) {
		return id, errors.New("metadata: malformed instance id or zone")
	}
	id.ProjectNumber, id.Zone = m[1], m[2]
	return id, nil
}

// ReadRelay reads the key relay's address (chutes-key-relay, "<IPv4>:<port>").
func (c *Client) ReadRelay(ctx context.Context) (string, error) {
	addr, err := c.Get(ctx, "instance/attributes/chutes-key-relay")
	if err != nil {
		return "", err
	}
	if !relayPattern.MatchString(addr) {
		return "", errors.New("metadata: chutes-key-relay is not <IPv4>:<port>")
	}
	return addr, nil
}
