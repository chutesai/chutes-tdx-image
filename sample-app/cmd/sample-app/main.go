// Command sample-app is Chutes' sample application for testing: it plays an owner's
// service behind tdx-gate (plaintext on 127.0.0.1 only).
//
//	POST /v1/echo           the request body, unchanged (200)
//	POST /v1/sealed-error   418 {"error":"teapot"} (a sealed application error)
//	POST /v1/stream         an SSE stream of a few events, then [DONE]
//	GET  /health            503 until --health-delay after start (the window stays open that
//	                        long), then 200
//	POST /v1/probe          the isolation probe (the probe build only: -tags probe)
//
// It lives on the encrypted app partition, so it runs only after the key window unlocked it.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// extraRoutes are added by build-tagged files (the probe).
var extraRoutes = map[string]http.HandlerFunc{}

func main() {
	listen := flag.String("listen", "127.0.0.1:9000", "loopback address (tdx-gate forwards here)")
	delay := flag.Duration("health-delay", 60*time.Second, "unhealthy this long after start")
	addWord := flag.Bool("echo-add-word", false, "append a word to each echoed message (an answer the extractive-output check refuses)")
	flag.Parse()
	started := time.Now()
	var healthy atomic.Bool

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		if !healthy.Load() && time.Since(started) >= *delay {
			healthy.Store(true)
		}
		if !healthy.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("POST /v1/echo", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 64<<20))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if *addWord {
			var v map[string]any
			if json.Unmarshal(body, &v) == nil {
				if msgs, ok := v["messages"].([]any); ok {
					for _, m := range msgs {
						if mm, ok := m.(map[string]any); ok {
							if s, ok := mm["content"].(string); ok {
								mm["content"] = s + " injected"
							}
						}
					}
				}
				body, _ = json.Marshal(v)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})
	mux.HandleFunc("POST /v1/sealed-error", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte(`{"error":"teapot"}`))
	})
	mux.HandleFunc("POST /v1/stream", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 64<<20))
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		for _, word := range strings.Fields("Analyze the following context carefully") {
			fmt.Fprintf(w, "data: {\"delta\":%q}\n\n", word+" ")
			if flusher != nil {
				flusher.Flush()
			}
			time.Sleep(50 * time.Millisecond)
		}
		fmt.Fprint(w, "data: [DONE]\n\n")
	})
	for path, h := range extraRoutes {
		mux.HandleFunc(path, h)
	}
	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	log.Printf("sample-app on %s (health after %s)", *listen, *delay)
	log.Fatal(srv.ListenAndServe())
}
