//go:build probe

package main

// The isolation probe, which tests the VM's network isolation: only in the probe build of the
// sample image, never in a customer image. POST /v1/probe {"key_service": "<ip>:<port>",
// "validator": "<ip>:<port>", "public": "<ip>:<port>"} tries, from inside the VM, each path the
// network must refuse, and returns what happened in its (sealed) answer.

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/chutesai/chutes-tdx-image/internal/metadata"
)

func init() {
	extraRoutes["POST /v1/probe"] = probe
}

type result struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
	MS     int64  `json:"ms"`
}

func try(name string, f func(ctx context.Context) (string, error)) result {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	start := time.Now()
	detail, err := f(ctx)
	r := result{Name: name, OK: err == nil, Detail: detail, MS: time.Since(start).Milliseconds()}
	if err != nil {
		r.Detail = err.Error()
	}
	return r
}

func tcp(addr string) func(ctx context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		if addr == "" {
			return "not asked", nil
		}
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
		if err != nil {
			return "", err
		}
		conn.Close()
		return "connected", nil
	}
}

func probe(w http.ResponseWriter, r *http.Request) {
	var in struct {
		KeyService string `json:"key_service"`
		Validator  string `json:"validator"`
		Public     string `json:"public"`
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	_ = json.Unmarshal(body, &in)
	if in.Public == "" {
		in.Public = "1.1.1.1:443"
	}
	md := metadata.New(metadata.Base)
	relay, _ := md.ReadRelay(r.Context())
	results := []result{
		try("tcp public "+in.Public, tcp(in.Public)),
		try("tcp key service "+in.KeyService, tcp(in.KeyService)),
		try("tcp key relay after close "+relay, tcp(relay)),
		try("tcp validator "+in.Validator, tcp(in.Validator)),
		try("tcp private.googleapis.com:443 (199.36.153.8)", tcp("199.36.153.8:443")),
		try("dns example.com via 169.254.169.254", func(ctx context.Context) (string, error) {
			res := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "udp", "169.254.169.254:53")
			}}
			addrs, err := res.LookupHost(ctx, "example.com")
			if err != nil {
				return "", err
			}
			return "answered " + addrs[0], nil
		}),
		try("metadata instance/id", func(ctx context.Context) (string, error) { return md.Get(ctx, "instance/id") }),
		try("metadata service-account token (must fail: no service account)", func(ctx context.Context) (string, error) {
			_, err := md.Get(ctx, "instance/service-accounts/default/token")
			if err != nil {
				return "", err
			}
			return "a token was served", nil
		}),
		try("ntp 169.254.169.254:123", func(ctx context.Context) (string, error) {
			conn, err := (&net.Dialer{}).DialContext(ctx, "udp", "169.254.169.254:123")
			if err != nil {
				return "", err
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			req := make([]byte, 48)
			req[0] = 0x23 // LI 0, version 4, client
			if _, err := conn.Write(req); err != nil {
				return "", err
			}
			resp := make([]byte, 48)
			if _, err := io.ReadFull(conn, resp); err != nil {
				return "", err
			}
			secs := binary.BigEndian.Uint32(resp[40:44])
			return time.Unix(int64(secs)-2208988800, 0).UTC().Format(time.RFC3339), nil
		}),
		try("tcp ipv6 [2606:4700:4700::1111]:443", tcp("[2606:4700:4700::1111]:443")),
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"probe": "chutes-sample-probe-v1", "results": results})
}
