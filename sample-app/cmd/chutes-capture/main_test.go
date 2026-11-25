package main

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestLineAndReportData(t *testing.T) {
	line := Line([]byte("quote"), []byte("ccel"))
	if !strings.HasPrefix(line, "CHUTES-CAPTURE-V1 ") || !strings.HasSuffix(line, "\n") {
		t.Fatalf("line %q", line)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(strings.TrimPrefix(line, "CHUTES-CAPTURE-V1 ")))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]string
	if err := json.Unmarshal(raw, &doc); err != nil || len(doc) != 2 || doc["quote"] != "cXVvdGU=" || doc["ccel"] != "Y2NlbA==" {
		t.Fatalf("doc %v", doc)
	}
	var nonce [32]byte
	nonce[0] = 7
	rd := ReportData(nonce)
	want := sha512.Sum512(append([]byte("chutes-tdx-capture-v1\x00"), nonce[:]...))
	if rd != want {
		t.Fatal("capture REPORTDATA")
	}
}
