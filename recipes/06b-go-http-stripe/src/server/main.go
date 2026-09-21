// fake-stripe is a tiny ledger protected by DNSid HTTP Message Signatures.
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/httpsig"
	"github.com/identity-digital/dnsid-cookbook/recipes/06b-go-http-stripe/src/internal/localregistry"
)

type ledger struct {
	mu       sync.Mutex
	balances map[string]int64
}

func (l *ledger) get(account string) int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.balances[account]
}

func (l *ledger) credit(account string, amount int64) int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.balances[account] += amount
	return l.balances[account]
}

type callerContextKey struct{}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	identity, _, err := localregistry.LoadIdentity(ctx)
	if err != nil {
		log.Fatal(err)
	}
	profile := httpsig.NewFromIdentityManager(identity, nil, httpsig.Config{})
	writers := splitCSV(os.Getenv("WRITER_DOMAINS"))
	book := &ledger{balances: map[string]int64{"acct_demo": 1000}}

	api := http.NewServeMux()
	api.HandleFunc("GET /v1/balance", func(w http.ResponseWriter, r *http.Request) {
		caller := r.Context().Value(callerContextKey{}).(*dnsid.VerifiedDomain)
		account := r.URL.Query().Get("account")
		if account == "" {
			account = "acct_demo"
		}
		log.Printf("verified GET /v1/balance from %s", caller.Domain())
		writeJSON(w, http.StatusOK, map[string]any{
			"account": account,
			"balance": book.get(account),
			"read_by": caller.Domain(),
		})
	})
	api.HandleFunc("POST /v1/balance/credit", func(w http.ResponseWriter, r *http.Request) {
		caller := r.Context().Value(callerContextKey{}).(*dnsid.VerifiedDomain)
		if !writers[caller.Domain()] {
			http.Error(w, "verified caller is not authorized to credit", http.StatusForbidden)
			return
		}
		var body struct {
			Account string `json:"account"`
			Amount  int64  `json:"amount"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Account == "" || body.Amount <= 0 {
			http.Error(w, "account and a positive amount are required", http.StatusBadRequest)
			return
		}
		balance := book.credit(body.Account, body.Amount)
		log.Printf("verified POST /v1/balance/credit from %s", caller.Domain())
		writeJSON(w, http.StatusOK, map[string]any{
			"account":     body.Account,
			"balance":     balance,
			"credited_by": caller.Domain(),
		})
	})

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, identity.GetKeySet().Raw())
	})
	mux.Handle("/v1/", authenticate(profile, api))

	port := os.Getenv("DNSID_AGENT_PORT")
	if port == "" {
		log.Fatal("DNSID_AGENT_PORT is required; run with `dnsid local run`")
	}
	log.Printf("fake-stripe ready on :%s; writers=%v", port, writers)
	server := &http.Server{Addr: ":" + port, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(server.ListenAndServe())
}

func authenticate(profile *httpsig.Profile, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil && r.Body != http.NoBody {
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		}
		// The local registry TLS proxy forwards plain HTTP. Restore the public request
		// URL because @target-uri covered the external HTTPS URL.
		publicRequest := r.Clone(r.Context())
		publicURL := *r.URL
		publicURL.Scheme = "https"
		publicURL.Host = r.Host
		publicRequest.URL = &publicURL
		publicRequest.Host = r.Host

		caller, err := profile.VerifyHTTPRequest(r.Context(), publicRequest)
		if err != nil {
			log.Printf("rejected unsigned or invalid request: %v", err)
			http.Error(w, "valid DNSid HTTP signature required", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, publicRequest.WithContext(context.WithValue(publicRequest.Context(), callerContextKey{}, caller)))
	})
}

func splitCSV(value string) map[string]bool {
	result := map[string]bool{}
	for item := range strings.SplitSeq(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			result[item] = true
		}
	}
	return result
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Printf("write response: %v", err)
	}
}
