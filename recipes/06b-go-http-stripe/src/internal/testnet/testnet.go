package testnet

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/log/c2sptlog"
)

func LoadIdentity(ctx context.Context) (*dnsid.IdentityManager, *http.Client, error) {
	transport := dnsid.TransportConfig{
		DNSServer:    os.Getenv("DNSID_DNS_SERVER"),
		CABundlePath: os.Getenv("DNSID_CA_BUNDLE"),
	}
	governanceDomain := os.Getenv("DNSID_GOVERNANCE_ID")
	policyURL := os.Getenv("DNSID_LOG_POLICY_URL")
	if transport.DNSServer == "" || transport.CABundlePath == "" || governanceDomain == "" || policyURL == "" {
		return nil, nil, fmt.Errorf("DNSid testnet environment is required; run with `dnsid testnet run`")
	}

	client, err := testnetHTTPClient(transport)
	if err != nil {
		return nil, nil, err
	}
	fetcher := &testnetFetcher{client: client, suffix: governanceDomain}
	registry, err := c2sptlog.NewVerificationRegistry(ctx, c2sptlog.VerificationRegistryConfig{
		PolicyURL:       policyURL,
		ResourceFetcher: fetcher,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("configure lifecycle log: %w", err)
	}
	identity, err := dnsid.NewIdentityManagerFromDnsid(
		"",
		// The CA bundle is consumed by the injected fetcher above; the SDK only
		// needs the DNS server for its own TXT lookups.
		dnsid.Config{Transport: dnsid.TransportConfig{DNSServer: transport.DNSServer}},
		dnsid.WithHTTPSFetcher(fetcher),
		dnsid.WithLogRegistry(registry),
	)
	if err != nil {
		return nil, nil, err
	}
	return identity, client, nil
}

// The production SDK rejects private destinations. The local testnet is
// private by design, so this client limits trust to its injected DNS server,
// CA, and .test zone instead.
func testnetHTTPClient(config dnsid.TransportConfig) (*http.Client, error) {
	client, err := dnsid.CreateDnsidHTTPClient(config)
	if err != nil {
		return nil, err
	}
	base, ok := client.Transport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("expected *http.Transport, got %T", client.Transport)
	}
	transport := base.Clone()
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, config.DNSServer)
		},
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		if net.ParseIP(host) != nil {
			return dialer.DialContext(ctx, network, address)
		}
		addresses, err := resolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		for _, address := range addresses {
			conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(address.IP.String(), port))
			if err == nil {
				return conn, nil
			}
		}
		return nil, fmt.Errorf("dial %s: no reachable address", host)
	}
	transport.DialTLSContext = nil
	client.Transport = transport
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return client, nil
}

type testnetFetcher struct {
	client *http.Client
	suffix string
}

func (f *testnetFetcher) FetchJSON(ctx context.Context, rawURL string, opts dnsid.FetchOptions) (json.RawMessage, *tls.Certificate, error) {
	if err := f.validateURL(rawURL, opts.AllowedHost, opts.DomainBoundary); err != nil {
		return nil, nil, err
	}
	data, cert, err := f.fetch(ctx, rawURL, opts.MaxResponseBytes)
	if err != nil {
		return nil, nil, err
	}

	// The testnet registry wraps su= in its agent-detail response.
	var envelope struct {
		ProtocolStatus json.RawMessage `json:"protocolStatus"`
	}
	if json.Unmarshal(data, &envelope) == nil && len(envelope.ProtocolStatus) > 0 {
		data = envelope.ProtocolStatus
	}
	return data, cert, nil
}

func (f *testnetFetcher) FetchBounded(ctx context.Context, rawURL string, maxBytes int64) ([]byte, error) {
	if err := f.validateURL(rawURL, "", false); err != nil {
		return nil, err
	}
	data, _, err := f.fetch(ctx, rawURL, maxBytes)
	return data, err
}

func (*testnetFetcher) SecurityGuarantees() c2sptlog.ResourceFetchGuarantees {
	return c2sptlog.ResourceFetchGuarantees{
		HTTPSOnly:                     true,
		RejectsRedirects:              true,
		ValidatesAllResolvedAddresses: true,
		ConnectsToValidatedAddress:    true,
		BoundsResponseDuringRead:      true,
	}
}

func (f *testnetFetcher) validateURL(rawURL, allowedHost string, domainBoundary bool) error {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return fmt.Errorf("invalid testnet HTTPS URL %q", rawURL)
	}
	host := strings.ToLower(u.Hostname())
	suffix := strings.ToLower(strings.TrimPrefix(f.suffix, "."))
	if host != suffix && !strings.HasSuffix(host, "."+suffix) {
		return fmt.Errorf("testnet HTTPS host %q is outside %q", host, suffix)
	}
	allowed := strings.ToLower(allowedHost)
	if allowed != "" && host != allowed && (!domainBoundary || !strings.HasSuffix(host, "."+allowed)) {
		return fmt.Errorf("testnet HTTPS host %q does not match %q", host, allowed)
	}
	return nil
}

func (f *testnetFetcher) fetch(ctx context.Context, rawURL string, maxBytes int64) ([]byte, *tls.Certificate, error) {
	if maxBytes <= 0 {
		maxBytes = 1 << 20
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, nil, err
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, nil, fmt.Errorf("testnet HTTPS fetch returned HTTP %s", resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, nil, fmt.Errorf("testnet HTTPS response exceeds %d bytes", maxBytes)
	}
	var cert *tls.Certificate
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		leaf := resp.TLS.PeerCertificates[0]
		cert = &tls.Certificate{Certificate: [][]byte{leaf.Raw}, Leaf: leaf}
	}
	return data, cert, nil
}
