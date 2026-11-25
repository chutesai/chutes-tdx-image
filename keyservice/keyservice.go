// Package keyservice is the REFERENCE key service: reference only, replace
// it with yours. It releases the app partition's key to a VM that proves, over the same TLS
// connection that will carry the key:
//
//   - a fresh, single-use nonce this service issued on this connection (60 s);
//   - its endpoint id is in this service's list of the owner's own endpoints (a copy of the image
//     booted under another account's endpoint gets nothing);
//   - a TDX quote whose REPORTDATA is keyrel.ReportData(tag, nonce, this connection's exporter,
//     endpoint id), verified by `chutes-tdx-measure verify-quote` with every row passing: Intel's
//     collateral and debug off (quote), the REPORTDATA (binding), the project pinned to Chutes'
//     customer-VM project (platform), the owner's signed measurement documents with the firmware
//     floor (measurements), and Google's provenance of the instance the VM names (provider_root:
//     MR_OWNER is the PZID of that instance, its host in Google's registry, MRCONFIGID and
//     MROWNERCONFIG zero). Provenance is mandatory.
//
// It logs the endpoint, the outcome and the failing rows: never the key.
//
// It bounds what any client of its public port can make it hold or run: a nonce
// is deleted when it is used or expires, at most MaxNonces are outstanding (beyond: 503
// nonce_busy), and at most MaxVerifies verify-quote processes run at once (the others wait for
// a slot, up to their connection's life).
package keyservice

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"sync"
	"time"

	"github.com/chutesai/chutes-tdx-image/internal/keyrel"
)

// ConfigSchema names the configuration.
const ConfigSchema = "chutes.reference-key-service-config.v1"

// VerifyConfig is what verify-quote needs besides the VM's own inputs.
type VerifyConfig struct {
	Command        []string `json:"command"`
	Documents      []string `json:"documents"`
	Signatures     []string `json:"signatures"`
	MeasurementKey string   `json:"measurement_key"`
	ImageSHA256    string   `json:"image_sha256"`
	MachineType    string   `json:"machine_type"`
	GCEProject     string   `json:"gce_project"`
	Floor          string   `json:"floor"`
	Platform       string   `json:"platform"`
	// FirmwareDir is verify-quote's firmware index (Google's endorsements and binaries by MRTD);
	// kept between verifications, so only a new firmware build is fetched during a window.
	FirmwareDir string `json:"firmware_dir"`
}

// Config is chutes.reference-key-service-config.v1.
type Config struct {
	Schema    string       `json:"schema"`
	Listen    string       `json:"listen"`
	TLSCert   string       `json:"tls_cert"`
	TLSKey    string       `json:"tls_key"`
	Tag       string       `json:"tag"`
	Endpoints []string     `json:"endpoints"`
	KeyFile   string       `json:"key_file"`
	NonceTTLS int          `json:"nonce_ttl_s"`
	Verify    VerifyConfig `json:"verify"`
}

var (
	hex64     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	gceID     = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)
	zoneRe    = regexp.MustCompile(`^[a-z]+(-[a-z]+)+[0-9]+-[a-z]$`)
	machineRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
)

func strictDecode(raw []byte, into any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}

// LoadConfig reads and checks the configuration.
func LoadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := strictDecode(raw, &c); err != nil {
		return nil, fmt.Errorf("keyservice: configuration: %w", err)
	}
	if c.Schema != ConfigSchema {
		return nil, fmt.Errorf("keyservice: schema must be %s", ConfigSchema)
	}
	if err := keyrel.CheckTag(c.Tag); err != nil {
		return nil, err
	}
	if len(c.Endpoints) == 0 {
		return nil, errors.New("keyservice: endpoints must list the owner's own endpoint ids")
	}
	for _, e := range c.Endpoints {
		if !keyrel.ValidEndpointID(e) {
			return nil, fmt.Errorf("keyservice: %q is not an endpoint id", e)
		}
	}
	v := c.Verify
	if len(v.Command) == 0 || len(v.Documents) == 0 || len(v.Documents) != len(v.Signatures) ||
		!hex64.MatchString(v.ImageSHA256) || !machineRe.MatchString(v.MachineType) || !gceID.MatchString(v.GCEProject) || v.MeasurementKey == "" {
		return nil, errors.New("keyservice: verify needs a command, documents with signatures, the measurement key, image_sha256, machine_type and gce_project")
	}
	if c.NonceTTLS <= 0 || c.NonceTTLS > 300 {
		return nil, errors.New("keyservice: nonce_ttl_s must be 1..300")
	}
	return &c, nil
}

// Rows are verify-quote's answer.
type Rows struct {
	Pass bool `json:"pass"`
	Rows []struct {
		Row    string `json:"row"`
		Status string `json:"status"`
		Code   string `json:"code"`
	} `json:"rows"`
}

// VerifyTimeout bounds one verify-quote run (a cold firmware index fetches Google's endorsement and
// binary, Intel's collateral and Google's registry). The VM waits longer per attempt
// (keyfetch.AttemptTimeout).
const VerifyTimeout = 120 * time.Second

// RequiredRows must each pass: provenance (provider_root) is mandatory.
var RequiredRows = []string{"quote", "binding", "platform", "measurements", "provider_root"}

// Verifier checks one quote.
type Verifier func(ctx context.Context, quote []byte, reportData [64]byte, inst keyrel.Instance) (Rows, error)

// CommandVerifier runs `verify-quote` with the configuration's inputs; the quote goes on stdin.
func CommandVerifier(v VerifyConfig) Verifier {
	return func(ctx context.Context, quote []byte, rd [64]byte, inst keyrel.Instance) (Rows, error) {
		args := append([]string(nil), v.Command[1:]...)
		args = append(args, "--quote", "-", "--report-data", hex.EncodeToString(rd[:]), "--documents")
		args = append(args, v.Documents...)
		args = append(args, "--signatures")
		args = append(args, v.Signatures...)
		args = append(args, "--measurement-key", v.MeasurementKey, "--image-sha256", v.ImageSHA256,
			"--machine-type", v.MachineType, "--gce-project", inst.ProjectNumber, "--allowed-project", v.GCEProject,
			"--zone", inst.Zone, "--instance-id", inst.InstanceID, "--json")
		if v.Floor != "" {
			args = append(args, "--floor", v.Floor)
		}
		if v.Platform != "" {
			args = append(args, "--platform", v.Platform)
		}
		if v.FirmwareDir != "" {
			args = append(args, "--firmware-dir", v.FirmwareDir)
		}
		ctx, cancel := context.WithTimeout(ctx, VerifyTimeout)
		defer cancel()
		cmd := exec.CommandContext(ctx, v.Command[0], args...)
		cmd.Stdin = bytes.NewReader([]byte(base64.StdEncoding.EncodeToString(quote)))
		out, err := cmd.Output()
		var rows Rows
		if jerr := json.Unmarshal(out, &rows); jerr != nil {
			if err == nil {
				err = jerr
			}
			return Rows{}, fmt.Errorf("verify-quote: %v", err)
		}
		return rows, nil
	}
}

type issued struct {
	nonce [32]byte
	at    time.Time
}

// MaxNonces is how many issued, unused, unexpired nonces the service keeps at once.
const MaxNonces = 4096

// MaxVerifies is how many verify-quote processes run at once.
const MaxVerifies = 4

// Service is the reference key service's HTTP handler.
type Service struct {
	cfg       *Config
	key       []byte
	verify    Verifier
	endpoints map[string]bool
	mu        sync.Mutex
	nonces    map[[32]byte]*issued // by the connection's exporter
	verifies  chan struct{}        // MaxVerifies slots
	now       func() time.Time
	log       *log.Logger
}

// New builds the service with the key (64 bytes) and a verifier.
func New(cfg *Config, key []byte, verify Verifier, logger *log.Logger) (*Service, error) {
	if len(key) != keyrel.KeySize {
		return nil, errors.New("keyservice: the key file must hold 64 bytes")
	}
	s := &Service{cfg: cfg, key: key, verify: verify, endpoints: map[string]bool{}, nonces: map[[32]byte]*issued{},
		verifies: make(chan struct{}, MaxVerifies), now: time.Now, log: logger}
	for _, e := range cfg.Endpoints {
		s.endpoints[e] = true
	}
	return s, nil
}

func answer(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func refuse(w http.ResponseWriter, status int, code string) {
	answer(w, status, map[string]string{"error": code})
}

func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil {
		refuse(w, http.StatusBadRequest, "tls_required")
		return
	}
	exporter, err := keyrel.Exporter(*r.TLS)
	if err != nil {
		refuse(w, http.StatusBadRequest, "tls13_required")
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/v1/nonce":
		var n [32]byte
		if _, err := rand.Read(n[:]); err != nil {
			refuse(w, http.StatusInternalServerError, "nonce")
			return
		}
		if !s.issue(exporter, n) {
			refuse(w, http.StatusServiceUnavailable, "nonce_busy")
			return
		}
		answer(w, http.StatusOK, keyrel.NonceAnswer{Nonce: hex.EncodeToString(n[:])})
	case r.Method == http.MethodPost && r.URL.Path == "/v1/release":
		s.release(w, r, exporter)
	default:
		refuse(w, http.StatusNotFound, "not_found")
	}
}

// issue records the connection's nonce (replacing its previous one), first dropping every expired
// nonce; false when MaxNonces are outstanding.
func (s *Service) issue(exporter, nonce [32]byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	ttl := time.Duration(s.cfg.NonceTTLS) * time.Second
	now := s.now()
	for k, n := range s.nonces {
		if now.Sub(n.at) > ttl {
			delete(s.nonces, k)
		}
	}
	if _, replacing := s.nonces[exporter]; !replacing && len(s.nonces) >= MaxNonces {
		return false
	}
	s.nonces[exporter] = &issued{nonce: nonce, at: now}
	return true
}

// SetClock replaces the clock (tests).
func (s *Service) SetClock(now func() time.Time) { s.now = now }

// Outstanding is the number of nonces the service holds (tests).
func (s *Service) Outstanding() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.nonces)
}

func (s *Service) release(w http.ResponseWriter, r *http.Request, exporter [32]byte) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	var req keyrel.ReleaseRequest
	if err != nil || strictDecode(raw, &req) != nil || !hex64.MatchString(req.Nonce) {
		refuse(w, http.StatusBadRequest, "bad_request")
		return
	}
	var nonce [32]byte
	_, _ = hex.Decode(nonce[:], []byte(req.Nonce))
	// The nonce: issued on this connection, unexpired, and used once (deleted now, pass or fail).
	s.mu.Lock()
	n := s.nonces[exporter]
	fresh := n != nil && subtle.ConstantTimeCompare(n.nonce[:], nonce[:]) == 1 &&
		s.now().Sub(n.at) <= time.Duration(s.cfg.NonceTTLS)*time.Second
	delete(s.nonces, exporter)
	s.mu.Unlock()
	if !fresh {
		refuse(w, http.StatusForbidden, "nonce_invalid")
		return
	}
	// The owner's own endpoints only.
	if !s.endpoints[req.EndpointID] {
		s.log.Printf("refused endpoint=%s reason=endpoint_not_listed", safe(req.EndpointID))
		refuse(w, http.StatusForbidden, "endpoint_not_listed")
		return
	}
	inst := req.Instance
	if !gceID.MatchString(inst.ProjectNumber) || !gceID.MatchString(inst.InstanceID) || !zoneRe.MatchString(inst.Zone) {
		refuse(w, http.StatusBadRequest, "bad_instance")
		return
	}
	if inst.ProjectNumber != s.cfg.Verify.GCEProject {
		s.log.Printf("refused endpoint=%s reason=project_not_pinned", req.EndpointID)
		refuse(w, http.StatusForbidden, "project_not_pinned")
		return
	}
	quote, err := base64.StdEncoding.DecodeString(req.QuoteB64)
	if err != nil || len(quote) == 0 || len(quote) > 32768 {
		refuse(w, http.StatusBadRequest, "bad_quote")
		return
	}
	rd := keyrel.ReportData(s.cfg.Tag, nonce, exporter, req.EndpointID)
	select { // a verify-quote slot, for as long as the connection lasts
	case s.verifies <- struct{}{}:
	case <-r.Context().Done():
		refuse(w, http.StatusServiceUnavailable, "verifier_busy")
		return
	}
	rows, err := s.verify(r.Context(), quote, rd, inst)
	<-s.verifies
	if err != nil {
		s.log.Printf("refused endpoint=%s reason=verifier_unavailable", req.EndpointID)
		refuse(w, http.StatusServiceUnavailable, "verifier_unavailable")
		return
	}
	if failed := failedRows(rows); len(failed) > 0 {
		s.log.Printf("refused endpoint=%s rows=%v", req.EndpointID, failed)
		refuse(w, http.StatusForbidden, "attestation_refused")
		return
	}
	s.log.Printf("released endpoint=%s instance=%s zone=%s", req.EndpointID, inst.InstanceID, inst.Zone)
	answer(w, http.StatusOK, keyrel.ReleaseAnswer{KeyB64: base64.StdEncoding.EncodeToString(s.key)})
}

// failedRows names every required row that is missing or did not pass (none: release).
func failedRows(rows Rows) []string {
	status := map[string]string{}
	for _, row := range rows.Rows {
		status[row.Row] = row.Status
	}
	var failed []string
	for _, name := range RequiredRows {
		if status[name] != "pass" {
			failed = append(failed, name)
		}
	}
	if !rows.Pass && len(failed) == 0 {
		failed = append(failed, "overall")
	}
	return failed
}

func safe(s string) string {
	if keyrel.ValidEndpointID(s) {
		return s
	}
	return "-"
}
