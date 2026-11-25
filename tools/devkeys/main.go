// Command devkeys makes a DEVELOPMENT set of key-window inputs for the sample image and the
// reference key service, in one private directory (mode 0700, files 0600 where secret). It
// prints nothing secret. Use them for testing only.
//
//	devkeys --dir keys --server-name sample-keys.chutes-tdx.invalid
//
// Writes: app.key (64 random bytes: the app key the key service releases), ca.pem and ca.key (a
// throwaway CA), service.pem and service.key (the key service's certificate for server_name),
// server_name, tag (the reference REPORTDATA tag).
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/chutesai/chutes-tdx-image/internal/keyrel"
)

func write(dir, name string, data []byte, mode os.FileMode) {
	if err := os.WriteFile(filepath.Join(dir, name), data, mode); err != nil {
		fmt.Fprintln(os.Stderr, "devkeys:", err)
		os.Exit(1)
	}
}

func main() {
	dir := flag.String("dir", "keys", "output directory (created mode 0700; must not exist)")
	name := flag.String("server-name", "sample-keys.chutes-tdx.invalid", "the key service's TLS name")
	flag.Parse()
	if err := os.Mkdir(*dir, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, "devkeys:", err)
		os.Exit(1)
	}
	key := make([]byte, keyrel.KeySize)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	write(*dir, "app.key", key, 0o600)
	now := time.Now().UTC()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "chutes-tdx-image dev CA (" + *name + ")"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(2, 0, 0), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, MaxPathLenZero: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		panic(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	svcKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	svcTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: *name}, DNSNames: []string{*name},
		NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(2, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	svcDER, err := x509.CreateCertificate(rand.Reader, svcTmpl, ca, &svcKey.PublicKey, caKey)
	if err != nil {
		panic(err)
	}
	pkcs8 := func(k *ecdsa.PrivateKey) []byte {
		der, _ := x509.MarshalPKCS8PrivateKey(k)
		return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	}
	write(*dir, "ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o644)
	write(*dir, "ca.key", pkcs8(caKey), 0o600)
	write(*dir, "service.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: svcDER}), 0o644)
	write(*dir, "service.key", pkcs8(svcKey), 0o600)
	write(*dir, "server_name", []byte(*name+"\n"), 0o644)
	write(*dir, "tag", []byte(keyrel.DefaultTag+"\n"), 0o644)
	fmt.Printf("dev key-window inputs written to %s (server name %s); keep the directory private\n", *dir, *name)
}
