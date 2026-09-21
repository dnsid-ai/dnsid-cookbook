// agent signs a read-credit-read flow with its local registry DNSid identity.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dnsid-ai/dnsid-go/httpsig"
	"github.com/identity-digital/dnsid-cookbook/recipes/06b-go-http-stripe/src/internal/localregistry"
)

type balanceResponse struct {
	Account    string `json:"account"`
	Balance    int64  `json:"balance"`
	ReadBy     string `json:"read_by"`
	CreditedBy string `json:"credited_by"`
}

func main() {
	serverURL := flag.String("server", "", "public fake-stripe HTTPS URL")
	account := flag.String("account", "acct_demo", "ledger account")
	amount := flag.Int64("amount", 250, "positive amount to credit")
	serve := flag.Bool("serve", false, "serve this identity's JWKS until interrupted")
	flag.Parse()
	if !*serve && (*serverURL == "" || *amount <= 0) {
		log.Fatal("--server and a positive --amount are required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	identity, client, err := localregistry.LoadIdentity(ctx)
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(identity.GetKeySet().Raw())
	})
	port := os.Getenv("DNSID_AGENT_PORT")
	if port == "" {
		log.Fatal("DNSID_AGENT_PORT is required; run with `dnsid local run`")
	}
	keyServer := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatal(err)
	}
	errCh := make(chan error, 1)
	go func() { errCh <- keyServer.Serve(listener) }()
	defer func() { _ = keyServer.Shutdown(context.Background()) }()

	if err := poll(ctx, func() error {
		_, err := identity.VerifyDomain(ctx, identity.Domain())
		return err
	}); err != nil {
		log.Fatalf("publish %s: %v", identity.Domain(), err)
	}
	fmt.Printf("verified identity: %s\n", identity.Domain())
	if *serve {
		fmt.Println("JWKS server ready; press Ctrl-C to stop")
		stop, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		<-stop.Done()
		return
	}

	unsigned, err := http.NewRequestWithContext(ctx, http.MethodGet, *serverURL+"/v1/balance?account="+*account, nil)
	if err != nil {
		log.Fatal(err)
	}
	resp, err := client.Do(unsigned)
	if err != nil {
		log.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		log.Fatalf("unsigned GET returned HTTP %s, want 401 Unauthorized", resp.Status)
	}
	fmt.Println("unsigned GET -> 401 Unauthorized")

	profile := httpsig.NewFromIdentityManagerKeyProvider(identity, httpsig.Config{})
	if err := expectTamperedBodyRejected(ctx, client, profile, *serverURL, *account); err != nil {
		log.Fatal(err)
	}
	fmt.Println("tampered POST -> 401 Unauthorized")

	balance, err := call(ctx, client, profile, http.MethodGet, *serverURL+"/v1/balance?account="+*account, nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("GET balance -> %d (verified as %s)\n", balance.Balance, balance.ReadBy)

	body, err := json.Marshal(map[string]any{"account": *account, "amount": *amount})
	if err != nil {
		log.Fatal(err)
	}
	balance, err = call(ctx, client, profile, http.MethodPost, *serverURL+"/v1/balance/credit", body)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("POST credit -> %d (verified as %s)\n", balance.Balance, balance.CreditedBy)

	balance, err = call(ctx, client, profile, http.MethodGet, *serverURL+"/v1/balance?account="+*account, nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("GET balance -> %d (verified as %s)\n", balance.Balance, balance.ReadBy)

	select {
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	default:
	}
}

func expectTamperedBodyRejected(ctx context.Context, client *http.Client, profile *httpsig.Profile, serverURL, account string) error {
	original, err := json.Marshal(map[string]any{"account": account, "amount": 1})
	if err != nil {
		return err
	}
	signed, err := signedRequest(ctx, profile, http.MethodPost, serverURL+"/v1/balance/credit", original)
	if err != nil {
		return err
	}
	tampered, err := json.Marshal(map[string]any{"account": account, "amount": 2})
	if err != nil {
		return err
	}
	signed.Body = io.NopCloser(bytes.NewReader(tampered))
	signed.ContentLength = int64(len(tampered))
	resp, err := client.Do(signed)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		return fmt.Errorf("tampered POST returned HTTP %s, want 401 Unauthorized", resp.Status)
	}
	return nil
}

func call(ctx context.Context, client *http.Client, profile *httpsig.Profile, method, target string, body []byte) (balanceResponse, error) {
	signed, err := signedRequest(ctx, profile, method, target, body)
	if err != nil {
		return balanceResponse{}, err
	}
	resp, err := client.Do(signed)
	if err != nil {
		return balanceResponse{}, err
	}
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return balanceResponse{}, err
	}
	if resp.StatusCode/100 != 2 {
		return balanceResponse{}, fmt.Errorf("%s %s returned HTTP %s: %s", method, target, resp.Status, responseBody)
	}
	var result balanceResponse
	if err := json.Unmarshal(responseBody, &result); err != nil {
		return balanceResponse{}, err
	}
	return result, nil
}

func signedRequest(ctx context.Context, profile *httpsig.Profile, method, target string, body []byte) (*http.Request, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return profile.CreateSignedHTTPRequest(req, httpsig.SigningOptions{ExpiresIn: time.Minute})
}

func poll(ctx context.Context, check func() error) error {
	var lastErr error
	for range 60 {
		if err := check(); err == nil {
			return nil
		} else {
			lastErr = err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return lastErr
}
