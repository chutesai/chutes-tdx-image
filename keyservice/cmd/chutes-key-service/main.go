// Command chutes-key-service is the REFERENCE key service: reference only, replace it with yours.
//
//	chutes-key-service --config /etc/chutes-key-service/config.json
//
// It serves the keyrel protocol over TLS 1.3 on the configured address and releases the key file's
// 64 bytes to a VM that passes every check of package keyservice (its endpoint in the list,
// `chutes-tdx-measure verify-quote` passing every row, Google's provenance included).
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/chutesai/chutes-tdx-image/keyservice"
)

func main() {
	path := flag.String("config", "/etc/chutes-key-service/config.json", "chutes.reference-key-service-config.v1")
	flag.Parse()
	logger := log.New(os.Stderr, "chutes-key-service: ", log.LstdFlags|log.LUTC)
	cfg, err := keyservice.LoadConfig(*path)
	if err != nil {
		logger.Fatal(err)
	}
	info, err := os.Stat(cfg.KeyFile)
	if err != nil {
		logger.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		logger.Fatalf("%s must not be readable by group or others", cfg.KeyFile)
	}
	key, err := os.ReadFile(cfg.KeyFile)
	if err != nil {
		logger.Fatal(err)
	}
	svc, err := keyservice.New(cfg, key, keyservice.CommandVerifier(cfg.Verify), logger)
	if err != nil {
		logger.Fatal(err)
	}
	cert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
	if err != nil {
		logger.Fatal(err)
	}
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           svc,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}},
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      180 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	fmt.Fprintln(os.Stderr, "chutes-key-service: REFERENCE ONLY, replace with your own key service")
	logger.Printf("serving %s for %d endpoint(s)", cfg.Listen, len(cfg.Endpoints))
	logger.Fatal(srv.ListenAndServeTLS("", ""))
}
