// Example workloads for DNSid cookbook recipe 16 (go-spiffe v2).
//
// One binary, three roles (ROLE env):
//
//	inventory     Acme internal HTTPS API  (mTLS; authorizes ALLOW_IDS)
//	supplier-api  Rackloria HTTPS API      (mTLS; authorizes ALLOW_IDS)
//	purchasing    Acme client that probes TARGETS (name|url|expected-spiffe-id, comma-separated)
//	              and reports results on a status port
//
// Layers are kept distinct in every result:
//
//	[SPIFFE] workload authentication: the mTLS handshake (X.509-SVID chains to the peer
//	         trust domain's bundle, delivered by the local SPIRE agent's Workload API)
//	[AuthZ]  workload authorization: the application's allow-list of peer SPIFFE IDs,
//	         evaluated AFTER authentication succeeds (HTTP 403 on deny)
//
// DNSid decisions are made elsewhere (the federation controller): they decide whether a
// trust domain's bundle is present at all. Workloads never see DNSid.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

var logger = slog.New(slog.NewJSONHandler(os.Stdout, nil))

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	ctx := context.Background()
	role := env("ROLE", "")
	src, err := waitForSource(ctx)
	if err != nil {
		logger.Error("workload API unavailable", "err", err)
		os.Exit(1)
	}
	defer src.Close()
	if s, err := src.GetX509SVID(); err == nil {
		logger.Info("svid", "layer", "SPIFFE", "role", role, "id", s.ID.String(),
			"expires", s.Certificates[0].NotAfter.UTC().Format(time.RFC3339))
	}
	switch role {
	case "inventory", "supplier-api":
		serve(src, role)
	case "purchasing":
		purchasing(src)
	default:
		logger.Error("unknown ROLE", "role", role)
		os.Exit(2)
	}
}

// waitForSource retries until the agent has attested us and issued an SVID.
func waitForSource(ctx context.Context) (*workloadapi.X509Source, error) {
	deadline := time.Now().Add(120 * time.Second)
	for {
		c, cancel := context.WithTimeout(ctx, 10*time.Second)
		src, err := workloadapi.NewX509Source(c)
		cancel()
		if err == nil {
			return src, nil
		}
		if time.Now().After(deadline) {
			return nil, err
		}
		logger.Info("waiting for SVID", "err", err.Error())
		time.Sleep(2 * time.Second)
	}
}

func svidID(src *workloadapi.X509Source) string {
	if s, err := src.GetX509SVID(); err == nil {
		return s.ID.String()
	}
	return ""
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// ---------------------------------------------------------------- servers

type authzStats struct {
	mu    sync.Mutex
	Allow int    `json:"allow"`
	Deny  int    `json:"deny"`
	Last  string `json:"last"`
}

func serve(src *workloadapi.X509Source, role string) {
	allowed := map[string]bool{}
	for _, s := range strings.Split(env("ALLOW_IDS", ""), ",") {
		if s = strings.TrimSpace(s); s != "" {
			allowed[spiffeid.RequireFromString(s).String()] = true
		}
	}
	stats := &authzStats{}

	mux := http.NewServeMux()
	handler := func(w http.ResponseWriter, r *http.Request) {
		peer := peerID(r)
		stats.mu.Lock()
		defer stats.mu.Unlock()
		if !allowed[peer] {
			stats.Deny++
			stats.Last = "deny " + peer
			logger.Warn("authz", "layer", "AuthZ", "decision", "deny", "peer", peer, "path", r.URL.Path)
			writeJSON(w, http.StatusForbidden, map[string]any{
				"layer": "AuthZ", "decision": "deny", "peer": peer,
				"reason": "peer SPIFFE ID authenticated but not on this API's allow-list"})
			return
		}
		stats.Allow++
		stats.Last = "allow " + peer
		logger.Info("authz", "layer", "AuthZ", "decision", "allow", "peer", peer, "path", r.URL.Path)
		if role == "supplier-api" {
			qty := 10
			_, _ = fmt.Sscan(r.URL.Query().Get("qty"), &qty)
			writeJSON(w, http.StatusOK, map[string]any{
				"supplier": "Rackloria", "sku": env("SKU", "USB-C-CABLE-1M"), "qty": qty,
				"unit_price_usd": 8.0, "total_usd": 8.0 * float64(qty),
				"served_by": svidID(src), "authorized_peer": peer, "note": "quote only; no order placed"})
		} else {
			writeJSON(w, http.StatusOK, map[string]any{
				"sku": env("SKU", "USB-C-CABLE-1M"), "on_hand": 3,
				"served_by": svidID(src), "authorized_peer": peer})
		}
	}
	mux.HandleFunc("/v1/", handler)

	// Authentication only at the TLS layer (AuthorizeAny = any peer whose SVID chains to
	// a bundle we hold for ITS trust domain). Authorization is the explicit app step above.
	tlsCfg := tlsconfig.MTLSServerConfig(src, src, tlsconfig.AuthorizeAny())
	srv := &http.Server{
		Addr: env("LISTEN", ":8443"), Handler: mux, TLSConfig: tlsCfg,
		ReadHeaderTimeout: 5 * time.Second,
		ErrorLog:          slogErrorLog("SPIFFE"),
	}
	go statusServer(func() any {
		stats.mu.Lock()
		defer stats.mu.Unlock()
		return map[string]any{"role": role, "svid": svidID(src), "allow_ids": keys(allowed),
			"authz": map[string]any{"allow": stats.Allow, "deny": stats.Deny, "last": stats.Last}}
	}, nil)
	logger.Info("listening", "role", role, "addr", srv.Addr, "allow_ids", keys(allowed))
	if err := srv.ListenAndServeTLS("", ""); err != nil {
		logger.Error("server stopped", "err", err)
		os.Exit(1)
	}
}

func peerID(r *http.Request) string {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return ""
	}
	id, err := x509svid.IDFromCert(r.TLS.PeerCertificates[0])
	if err != nil {
		return ""
	}
	return id.String()
}

func keys(m map[string]bool) []string {
	out := []string{}
	for k := range m {
		out = append(out, k)
	}
	return out
}

// slogErrorLog routes net/http's TLS handshake errors into structured logs tagged [SPIFFE].
func slogErrorLog(layer string) *log.Logger { return log.New(&logAdapter{layer: layer}, "", 0) }

type logAdapter struct{ layer string }

func (l *logAdapter) Write(p []byte) (int, error) {
	logger.Warn("handshake", "layer", l.layer, "msg", strings.TrimSpace(string(p)))
	return len(p), nil
}

// ---------------------------------------------------------------- purchasing client

type target struct {
	Name string `json:"name"`
	URL  string `json:"url"`
	ID   string `json:"expected_id"`
	id   spiffeid.ID

	held      *http.Client
	heldMu    sync.Mutex
	heldDials int
	heldDead  bool
}

type result struct {
	At      string `json:"at"`
	OK      bool   `json:"ok"`
	Layer   string `json:"layer,omitempty"` // SPIFFE | AuthZ | NETWORK | HTTP
	Status  int    `json:"status,omitempty"`
	Detail  string `json:"detail"`
	Reused  *bool  `json:"reused,omitempty"`
	Elapsed string `json:"elapsed"`
}

type probeOut struct {
	New  result `json:"new_handshake"`
	Held result `json:"held_connection"`
}

func purchasing(src *workloadapi.X509Source) {
	var ts []*target
	for _, s := range strings.Split(env("TARGETS", ""), ",") {
		p := strings.SplitN(strings.TrimSpace(s), "|", 3)
		if len(p) != 3 {
			continue
		}
		t := &target{Name: p[0], URL: p[1], ID: p[2], id: spiffeid.RequireFromString(p[2])}
		t.resetHeld(src)
		ts = append(ts, t)
	}
	var mu sync.Mutex
	last := map[string]probeOut{}
	probeAll := func() map[string]probeOut {
		out := map[string]probeOut{}
		for _, t := range ts {
			out[t.Name] = probeOut{New: t.probeNew(src), Held: t.probeHeld()}
			logger.Info("probe", "target", t.Name, "new_ok", out[t.Name].New.OK,
				"new_layer", out[t.Name].New.Layer, "new_detail", out[t.Name].New.Detail,
				"held_ok", out[t.Name].Held.OK, "held_detail", out[t.Name].Held.Detail)
		}
		mu.Lock()
		for k, v := range out {
			last[k] = v
		}
		mu.Unlock()
		return out
	}
	iv, err := time.ParseDuration(env("INTERVAL", "2s"))
	if err != nil || iv <= 0 {
		iv = 2 * time.Second
	}
	go func() {
		for {
			probeAll()
			time.Sleep(iv)
		}
	}()
	extra := http.NewServeMux()
	extra.HandleFunc("/probe", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"svid": svidID(src), "results": probeAll()})
	})
	extra.HandleFunc("/held/reset", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		for _, t := range ts {
			t.resetHeld(src)
		}
		writeJSON(w, http.StatusOK, map[string]any{"held": "reset"})
	})
	statusServer(func() any {
		mu.Lock()
		defer mu.Unlock()
		cp := map[string]probeOut{}
		for k, v := range last {
			cp[k] = v
		}
		return map[string]any{"role": "purchasing", "svid": svidID(src), "targets": ts, "results": cp}
	}, extra)
}

func (t *target) mtls(src *workloadapi.X509Source) *tls.Config {
	// [SPIFFE] authentication + pinning the expected server identity for this target.
	return tlsconfig.MTLSClientConfig(src, src, tlsconfig.AuthorizeID(t.id))
}

// probeNew performs a brand-new TLS handshake (no connection reuse), so it always uses the
// bundles the agent is delivering right now.
func (t *target) probeNew(src *workloadapi.X509Source) result {
	tr := &http.Transport{TLSClientConfig: t.mtls(src), DisableKeepAlives: true,
		TLSHandshakeTimeout: 3 * time.Second}
	defer tr.CloseIdleConnections()
	return do(&http.Client{Transport: tr, Timeout: 5 * time.Second}, t.URL)
}

// resetHeld creates a client that dials exactly once. After that connection dies it refuses to
// redial, so we can observe what bundle withdrawal does to an ESTABLISHED session.
func (t *target) resetHeld(src *workloadapi.X509Source) {
	t.heldMu.Lock()
	defer t.heldMu.Unlock()
	if t.held != nil {
		t.held.CloseIdleConnections()
	}
	t.heldDials, t.heldDead = 0, false
	cfg := t.mtls(src)
	tr := &http.Transport{
		MaxConnsPerHost: 1, MaxIdleConnsPerHost: 1, IdleConnTimeout: 0,
		TLSHandshakeTimeout: 3 * time.Second,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			t.heldMu.Lock()
			if t.heldDials > 0 {
				t.heldDead = true
				t.heldMu.Unlock()
				return nil, errors.New("held connection closed; not redialing (POST /held/reset to reopen)")
			}
			t.heldDials++
			t.heldMu.Unlock()
			d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 3 * time.Second}, Config: cfg}
			c, err := d.DialContext(ctx, network, addr)
			if err != nil {
				t.heldMu.Lock()
				t.heldDials = 0 // never established: allow a later first attempt
				t.heldMu.Unlock()
			}
			return c, err
		},
	}
	t.held = &http.Client{Transport: tr, Timeout: 5 * time.Second}
}

func (t *target) probeHeld() result {
	t.heldMu.Lock()
	c, dead := t.held, t.heldDead
	t.heldMu.Unlock()
	if dead {
		return result{At: now(), OK: false, Layer: "NETWORK", Detail: "held connection closed earlier; not redialing"}
	}
	return do(c, t.URL)
}

func do(c *http.Client, url string) result {
	start := time.Now()
	var reused *bool
	trace := &httptrace.ClientTrace{GotConn: func(i httptrace.GotConnInfo) { r := i.Reused; reused = &r }}
	req, _ := http.NewRequestWithContext(httptrace.WithClientTrace(context.Background(), trace), "GET", url, nil)
	resp, err := c.Do(req)
	res := result{At: now(), Reused: reused}
	defer func() { res.Elapsed = time.Since(start).Round(time.Millisecond).String() }()
	if err != nil {
		res.Layer, res.Detail = classify(err), short(err.Error())
		res.Elapsed = time.Since(start).Round(time.Millisecond).String()
		return res
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	res.Status = resp.StatusCode
	res.Reused = reused
	res.Elapsed = time.Since(start).Round(time.Millisecond).String()
	switch {
	case resp.StatusCode == http.StatusForbidden:
		res.Layer, res.Detail = "AuthZ", short(string(body))
	case resp.StatusCode != http.StatusOK:
		res.Layer, res.Detail = "HTTP", short(string(body))
	default:
		res.OK, res.Detail = true, strings.TrimSpace(string(body)) // full JSON body (<=4 KiB)
	}
	return res
}

func classify(err error) string {
	s := err.Error()
	for _, k := range []string{"x509", "bundle", "certificate", "tls:", "handshake", "SPIFFE", "spiffe"} {
		if strings.Contains(s, k) {
			return "SPIFFE"
		}
	}
	return "NETWORK"
}

func short(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 220 {
		s = s[:220] + "…"
	}
	return s
}

func now() string { return time.Now().UTC().Format("2006-01-02T15:04:05.000Z") }

// statusServer serves plain-HTTP status (bound to localhost on the host by Compose).
func statusServer(status func() any, extra *http.ServeMux) {
	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, http.StatusOK, status()) })
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
	})
	if extra != nil {
		mux.Handle("/probe", extra)
		mux.Handle("/held/", extra)
	}
	srv := &http.Server{Addr: env("STATUS_LISTEN", ":8080"), Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	if err := srv.ListenAndServe(); err != nil {
		logger.Error("status server stopped", "err", err)
		os.Exit(1)
	}
}
