// Command chutes-key-fetch is the VM's side of the key window, then the app partition's unlock:
//
//	chutes-key-fetch --config /etc/chutes-key-fetch.json --unlock
//
// It reads chutes-key-relay, chutes-endpoint-id, instance/id and instance/zone from the metadata
// server, fetches the key (keyfetch.Fetch: retries until it has it), derives this image's data key
// from it and checks it against the image's check value (a mismatch prints key_check_failed on
// the serial console and stops: no retry fixes another image's key), then maps the app partition:
// dm-verity over the ciphertext (the root hash is the kernel command line's chutes.app_roothash=,
// which the UKI measures), then plain dm-crypt (aes-xts-plain64) on top with the data key on
// cryptsetup's standard input. No key is written to disk or logged.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/chutesai/chutes-tdx-image/internal/metadata"
	"github.com/chutesai/chutes-tdx-image/internal/tsm"
	"github.com/chutesai/chutes-tdx-image/keyfetch"
)

const (
	appData   = "/dev/disk/by-partlabel/chutes-app"
	appHash   = "/dev/disk/by-partlabel/chutes-app-verity"
	verityMap = "chutes-app-verity"
	cryptMap  = "chutes-app"
)

var roothashPattern = regexp.MustCompile(`(?:^|\s)chutes\.app_roothash=([0-9a-f]{64})(?:\s|$)`)

func appRootHash() (string, error) {
	raw, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return "", err
	}
	m := roothashPattern.FindStringSubmatch(strings.TrimSpace(string(raw)))
	if m == nil {
		return "", errors.New("the kernel command line has no chutes.app_roothash=<64 hex>")
	}
	return m[1], nil
}

func run(stdin []byte, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %v: %s", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func unlock(key []byte) error {
	roothash, err := appRootHash()
	if err != nil {
		return err
	}
	if err := run(nil, "veritysetup", "open", appData, verityMap, appHash, roothash); err != nil {
		return err
	}
	// The key arrives on standard input as a key file (/dev/stdin): plain mode would hash it as a
	// passphrase if it were named "-".
	return run(key, "cryptsetup", "open", "--type", "plain", "--cipher", "aes-xts-plain64", "--key-size", "512",
		"--key-file", "/dev/stdin", "--keyfile-size", "64", "--readonly", "/dev/mapper/"+verityMap, cryptMap)
}

func main() {
	configPath := flag.String("config", "/etc/chutes-key-fetch.json", "the key service's name, CA and tag")
	doUnlock := flag.Bool("unlock", false, "map the app partition with the key (verity, then dm-crypt)")
	metadataBase := flag.String("metadata-base", metadata.Base, "the metadata server (tests)")
	tsmDir := flag.String("tsm-dir", tsm.DefaultDir, "the configfs-tsm report directory")
	flag.Parse()
	logger := log.New(os.Stderr, "chutes-key-fetch: ", 0)

	cfg, err := keyfetch.LoadConfig(*configPath)
	if err != nil {
		logger.Fatal(err)
	}
	md := metadata.New(*metadataBase)
	ctx := context.Background()
	var f keyfetch.Fetcher
	for delay := time.Second; ; delay = min(delay*2, 30*time.Second) {
		id, err := md.ReadIdentity(ctx)
		if err == nil {
			relay, rerr := md.ReadRelay(ctx)
			if rerr == nil {
				f = keyfetch.Fetcher{Config: cfg, Quoter: &tsm.Configfs{Dir: *tsmDir}, Identity: id, RelayAddr: relay, Logf: logger.Printf}
				break
			}
			err = rerr
		}
		logger.Printf("metadata: %v; retrying in %s", err, delay)
		time.Sleep(delay)
	}
	released, err := f.Fetch(ctx)
	if err != nil {
		logger.Fatal(err)
	}
	key, err := cfg.DataKey(released)
	clear(released)
	if err != nil {
		logger.Fatal(err) // key_check_failed: before cryptsetup, on the console
	}
	if *doUnlock {
		err = unlock(key)
	}
	clear(key)
	if err != nil {
		logger.Fatal(err)
	}
	logger.Print("done")
}
