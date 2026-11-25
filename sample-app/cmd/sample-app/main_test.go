package main

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// The sample app runs as a process on loopback (its handlers are in main).
func TestSampleApp(t *testing.T) {
	if os.Getenv("SAMPLE_APP_CHILD") == "1" {
		os.Args = []string{"sample-app", "--listen", os.Getenv("SAMPLE_APP_LISTEN"), "--health-delay", "3s"}
		main()
		return
	}
	addr := "127.0.0.1:19087"
	cmd := exec.Command(os.Args[0], "-test.run", "TestSampleApp")
	cmd.Env = append(os.Environ(), "SAMPLE_APP_CHILD=1", "SAMPLE_APP_LISTEN="+addr)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	base := "http://" + addr
	var resp *http.Response
	var err error
	for i := 0; i < 50; i++ {
		if resp, err = http.Get(base + "/health"); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 503 {
		t.Fatalf("healthy before the delay: %d", resp.StatusCode)
	}
	time.Sleep(3200 * time.Millisecond)
	if resp, _ = http.Get(base + "/health"); resp.StatusCode != 200 {
		t.Fatalf("not healthy after the delay: %d", resp.StatusCode)
	}
	body := `{"messages":[{"role":"user","content":"hi"}]}`
	resp, _ = http.Post(base+"/v1/echo", "application/json", strings.NewReader(body))
	got, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(got) != body {
		t.Fatalf("echo %d %s", resp.StatusCode, got)
	}
	resp, _ = http.Post(base+"/v1/sealed-error", "application/json", strings.NewReader("{}"))
	got, _ = io.ReadAll(resp.Body)
	if resp.StatusCode != 418 || string(got) != `{"error":"teapot"}` {
		t.Fatalf("sealed-error %d %s", resp.StatusCode, got)
	}
	resp, _ = http.Post(base+"/v1/stream", "application/json", strings.NewReader(`{"stream":true}`))
	got, _ = io.ReadAll(resp.Body)
	if resp.Header.Get("Content-Type") != "text/event-stream" || !bytes.HasSuffix(got, []byte("data: [DONE]\n\n")) {
		t.Fatalf("stream %q", got)
	}
	if resp, _ = http.Post(base+"/v1/probe", "application/json", strings.NewReader("{}")); resp.StatusCode != 404 && resp.StatusCode != 405 {
		t.Fatalf("the probe is served without the probe build: %d", resp.StatusCode)
	}
}
