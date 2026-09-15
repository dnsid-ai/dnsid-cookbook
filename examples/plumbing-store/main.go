// Ace Plumbing Co. — DNSid provenance demo.
//
// Demonstrates how a business can sign quote documents with an Ed25519 key
// anchored to a domain identity (_dnsid TXT record), and how anyone can
// independently verify that signature by resolving that record.
//
// Run: go run .
// Open: http://localhost:8080
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	shopFQDN   = "ace-plumbing.example"
	listenAddr = ":8080"
)

// mockDNS simulates _dnsid TXT record resolution for the demo domain.
// In production this is a real DNS TXT lookup: _dnsid.<issuer> → ku=<jwks-url> ...
var mockDNS = map[string]string{
	shopFQDN: "http://localhost:8080/.well-known/jwks.json",
}

var (
	privKey ed25519.PrivateKey
	pubKey  ed25519.PublicKey
	keyID   string
)

// ---- Data types ----

type LineItem struct {
	Description string  `json:"description"`
	Price       float64 `json:"price"`
}

type Quote struct {
	ID           string
	CustomerName string
	Problem      string
	Items        []LineItem
	Total        float64
	CreatedAt    time.Time
	JWT          string
}

var (
	quotes   = map[string]*Quote{}
	quotesMu sync.RWMutex
)

// ---- Entry point ----

func main() {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("keygen: %v", err)
	}
	pubKey, privKey = pub, priv
	keyID = jwkThumbprint(pub)

	log.Printf("Key ID: %s", keyID)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", handleIndex)
	mux.HandleFunc("POST /chat", handleChat)
	mux.HandleFunc("GET /quote/{id}", handleQuote)
	mux.HandleFunc("GET /verify", handleVerifyPage)
	mux.HandleFunc("POST /api/verify", handleVerifyAPI)
	mux.HandleFunc("GET /.well-known/jwks.json", handleJWKS)

	log.Printf("Ace Plumbing Co. running at http://localhost%s", listenAddr)
	log.Fatal(http.ListenAndServe(listenAddr, mux))
}

// ---- Handlers ----

func handleIndex(w http.ResponseWriter, r *http.Request) {
	renderTemplate(w, indexTmpl, nil)
}

func handleChat(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Customer string `json:"customer"`
		Message  string `json:"message"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	req.Customer = strings.TrimSpace(req.Customer)
	req.Message = strings.TrimSpace(req.Message)
	if req.Customer == "" {
		req.Customer = "Valued Customer"
	}
	if req.Message == "" {
		writeJSON(w, map[string]any{"reply": "Please describe your plumbing problem and I'll put together an estimate."})
		return
	}

	items, total := priceProblem(req.Message)
	qID := randomID()
	jwt, err := signQuoteJWT(qID, req.Customer, total)
	if err != nil {
		http.Error(w, "signing failed", http.StatusInternalServerError)
		return
	}

	q := &Quote{
		ID:           qID,
		CustomerName: req.Customer,
		Problem:      req.Message,
		Items:        items,
		Total:        total,
		CreatedAt:    time.Now(),
		JWT:          jwt,
	}
	quotesMu.Lock()
	quotes[qID] = q
	quotesMu.Unlock()

	var reply string
	switch {
	case total < 200:
		reply = fmt.Sprintf("Good news — that's a quick fix! Your estimate comes to $%.2f. I've put together a full quote for you.", total)
	case total < 500:
		reply = fmt.Sprintf("We can take care of that. Your estimate is $%.2f. Here's your detailed quote.", total)
	default:
		reply = fmt.Sprintf("That's a significant repair and best handled promptly. Your estimate is $%.2f. Full details in your quote.", total)
	}

	writeJSON(w, map[string]any{
		"reply":     reply,
		"quote_id":  qID,
		"quote_url": "/quote/" + qID,
	})
}

func handleQuote(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	quotesMu.RLock()
	q, ok := quotes[id]
	quotesMu.RUnlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	renderTemplate(w, quoteTmpl, q)
}

func handleVerifyPage(w http.ResponseWriter, r *http.Request) {
	renderTemplate(w, verifyTmpl, nil)
}

func handleVerifyAPI(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]any{"valid": false, "error": "invalid request body"})
		return
	}
	result := verifyToken(r.Context(), strings.TrimSpace(req.Token))
	writeJSON(w, result)
}

func handleJWKS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "max-age=300")
	json.NewEncoder(w).Encode(map[string]any{
		"keys": []map[string]any{{
			"kty": "OKP",
			"crv": "Ed25519",
			"x":   base64.RawURLEncoding.EncodeToString(pubKey),
			"kid": keyID,
			"use": "sig",
			"alg": "EdDSA",
		}},
	})
}

// ---- Pricing ----

func priceProblem(problem string) ([]LineItem, float64) {
	p := strings.ToLower(problem)
	var items []LineItem

	add := func(desc string, cost float64) {
		items = append(items, LineItem{desc, cost})
	}

	if anyContains(p, "faucet", "drip", "tap", "dripping") {
		add("Faucet repair (labor + cartridge)", 150.00)
	}
	if anyContains(p, "drain", "clog", "clogged", "slow drain") {
		add("Drain cleaning", 95.00)
	}
	if anyContains(p, "toilet", "flush", "flapper", "running toilet") {
		add("Toilet repair (parts + labor)", 120.00)
	}
	if anyContains(p, "pipe", "burst", "broken pipe", "cracked") {
		add("Emergency pipe repair (materials + labor)", 395.00)
		add("Emergency call-out surcharge", 75.00)
	}
	if anyContains(p, "leak", "leaking", "water damage") && !anyContains(p, "pipe", "burst") {
		add("Leak detection + repair", 220.00)
	}
	if anyContains(p, "water heater", "hot water", "no hot water", "heater") {
		add("Water heater diagnosis + repair", 280.00)
	}
	if anyContains(p, "sewer", "sewage", "smell", "odor", "backup") {
		add("Sewer line inspection (camera)", 200.00)
		add("Hydro-jet cleaning", 350.00)
	}
	if anyContains(p, "low pressure", "water pressure", "weak flow") {
		add("Pressure regulator inspection + adjustment", 110.00)
	}
	if len(items) == 0 {
		add("Plumbing inspection + diagnostic", 85.00)
		add("Standard repair (estimated)", 150.00)
	}

	add("Service call fee", 65.00)

	var total float64
	for _, it := range items {
		total += it.Price
	}
	return items, total
}

func anyContains(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// ---- JWT signing ----

func signQuoteJWT(quoteID, customer string, amount float64) (string, error) {
	now := time.Now()
	headerJSON, _ := json.Marshal(map[string]any{
		"alg": "EdDSA",
		"typ": "JWT",
		"kid": keyID,
	})
	payloadJSON, _ := json.Marshal(map[string]any{
		"iss":      shopFQDN,
		"sub":      "quote:" + quoteID,
		"aud":      "customer",
		"iat":      now.Unix(),
		"exp":      now.Add(24 * time.Hour).Unix(),
		"quote_id": quoteID,
		"customer": customer,
		"amount":   amount,
	})

	h64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	p64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	input := h64 + "." + p64
	sig := ed25519.Sign(privKey, []byte(input))
	return input + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// ---- JWT verification ----

type verifyResult struct {
	Valid   bool           `json:"valid"`
	Error   string         `json:"error,omitempty"`
	Issuer  string         `json:"issuer,omitempty"`
	JWKSURL string         `json:"jwks_url,omitempty"`
	Claims  map[string]any `json:"claims,omitempty"`
	Steps   []string       `json:"steps"`
}

func verifyToken(ctx context.Context, token string) verifyResult {
	var steps []string

	fail := func(msg string) verifyResult {
		steps = append(steps, "✗ "+msg)
		return verifyResult{Valid: false, Error: msg, Steps: steps}
	}
	ok := func(msg string) { steps = append(steps, "✓ "+msg) }

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fail("Malformed JWT: expected header.payload.signature")
	}
	ok("Parsed JWT (3 parts)")

	hBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fail("Cannot base64-decode JWT header")
	}
	var header map[string]any
	if json.Unmarshal(hBytes, &header) != nil {
		return fail("Cannot parse JWT header JSON")
	}
	alg, okAlg := header["alg"].(string)
	if !okAlg || alg == "" {
		return fail("Missing alg header")
	}
	if alg != "EdDSA" {
		return fail(fmt.Sprintf("Unsupported alg %q: expected EdDSA", alg))
	}
	reqKID, okKID := header["kid"].(string)
	if !okKID || reqKID == "" {
		return fail("Missing kid header")
	}
	ok(fmt.Sprintf("Decoded header — alg=%s kid=%s", alg, reqKID))

	pBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fail("Cannot base64-decode JWT payload")
	}
	var claims map[string]any
	if json.Unmarshal(pBytes, &claims) != nil {
		return fail("Cannot parse JWT payload JSON")
	}

	issuer, _ := claims["iss"].(string)
	if issuer == "" {
		return fail("Missing iss claim")
	}
	ok(fmt.Sprintf("Extracted issuer: %s", issuer))

	// Step 1: DNS resolution — look up _dnsid TXT record for the issuer domain.
	// In production: net.LookupTXT("_dnsid." + issuer) and parse ku= field.
	jwksURL, found := mockDNS[issuer]
	if !found {
		return fail(fmt.Sprintf("DNS: no _dnsid TXT record found for %s", issuer))
	}
	ok(fmt.Sprintf("DNS: _dnsid.%s → ku=%s", issuer, jwksURL))

	// Step 2: Fetch JWKS from the URL in the record.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return fail(fmt.Sprintf("Invalid JWKS URL: %v", err))
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fail(fmt.Sprintf("JWKS fetch failed: %v", err))
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fail(fmt.Sprintf("JWKS fetch returned HTTP %d", resp.StatusCode))
	}

	var jwksDoc struct {
		Keys []map[string]any `json:"keys"`
	}
	if json.NewDecoder(resp.Body).Decode(&jwksDoc) != nil || len(jwksDoc.Keys) == 0 {
		return fail("Invalid or empty JWKS response")
	}
	ok(fmt.Sprintf("Fetched JWKS (%d key(s))", len(jwksDoc.Keys)))

	// Step 3: Find matching key by kid.
	var matchedKey map[string]any
	for _, k := range jwksDoc.Keys {
		if k["kid"] == reqKID {
			matchedKey = k
			break
		}
	}
	if matchedKey == nil {
		return fail(fmt.Sprintf("No JWKS key matched kid=%s", reqKID))
	}
	if kty, _ := matchedKey["kty"].(string); kty != "OKP" {
		return fail(fmt.Sprintf("JWKS key kid=%s has kty=%v; expected OKP", reqKID, matchedKey["kty"]))
	}
	if crv, _ := matchedKey["crv"].(string); crv != "Ed25519" {
		return fail(fmt.Sprintf("JWKS key kid=%s has crv=%v; expected Ed25519", reqKID, matchedKey["crv"]))
	}
	if jwkAlg, _ := matchedKey["alg"].(string); jwkAlg != "EdDSA" {
		return fail(fmt.Sprintf("JWKS key kid=%s has alg=%v; expected EdDSA", reqKID, matchedKey["alg"]))
	}
	if useValue, found := matchedKey["use"]; found {
		use, ok := useValue.(string)
		if !ok || use != "sig" {
			return fail(fmt.Sprintf("JWKS key kid=%s has use=%v; expected sig", reqKID, useValue))
		}
	}
	xStr, _ := matchedKey["x"].(string)
	keyBytes, err := base64.RawURLEncoding.DecodeString(xStr)
	if err != nil || len(keyBytes) != ed25519.PublicKeySize {
		return fail("Invalid Ed25519 public key in JWKS")
	}
	ok(fmt.Sprintf("Found key kid=%v", matchedKey["kid"]))

	// Step 4: Verify EdDSA (Ed25519) signature.
	sigInput := parts[0] + "." + parts[1]
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fail("Cannot base64-decode signature")
	}
	if !ed25519.Verify(ed25519.PublicKey(keyBytes), []byte(sigInput), sig) {
		return fail("EdDSA signature verification FAILED")
	}
	ok("EdDSA (Ed25519) signature verified")

	// Step 5: Validate time claims.
	expValue, found := claims["exp"]
	if !found {
		return fail("Missing exp claim")
	}
	exp, isNum := expValue.(float64)
	if !isNum {
		return fail("exp claim must be numeric")
	}
	expTime := time.Unix(int64(exp), 0)
	if time.Now().After(expTime) {
		return fail(fmt.Sprintf("Token expired at %s", expTime.Format(time.RFC1123)))
	}
	ok(fmt.Sprintf("Not expired (exp: %s)", expTime.Format(time.RFC1123)))

	return verifyResult{
		Valid:   true,
		Issuer:  issuer,
		JWKSURL: jwksURL,
		Claims:  claims,
		Steps:   steps,
	}
}

// ---- Helpers ----

func jwkThumbprint(pub ed25519.PublicKey) string {
	x := base64.RawURLEncoding.EncodeToString(pub)
	// RFC 7638: SHA-256 of canonical JWK JSON with alphabetically sorted keys.
	canonical := fmt.Sprintf(`{"crv":"Ed25519","kty":"OKP","x":"%s"}`, x)
	h := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func randomID() string {
	b := make([]byte, 4)
	rand.Read(b) //nolint:errcheck
	return fmt.Sprintf("Q-%04X", b)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func renderTemplate(w http.ResponseWriter, src string, data any) {
	t, err := template.New("").Funcs(template.FuncMap{
		"currency": func(f float64) string { return fmt.Sprintf("$%.2f", f) },
		"fmtTime":  func(t time.Time) string { return t.Format("January 2, 2006") },
	}).Parse(src)
	if err != nil {
		http.Error(w, "template error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.Execute(w, data); err != nil {
		log.Printf("template execute: %v", err)
	}
}

// ---- HTML Templates ----

const indexTmpl = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Ace Plumbing Co.</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #f0f4f8; min-height: 100vh; }
header { background: #1e3a5f; color: #fff; padding: 1rem 1.5rem; display: flex; align-items: center; gap: 0.75rem; }
header h1 { font-size: 1.25rem; font-weight: 600; }
header p { font-size: 0.85rem; opacity: 0.75; margin-top: 0.2rem; }
.logo { font-size: 2rem; }
nav a { color: #a8d0f0; font-size: 0.85rem; text-decoration: none; margin-left: 1.5rem; }
nav a:hover { color: #fff; }
.header-inner { display: flex; align-items: center; flex: 1; }
.chat-wrap { max-width: 680px; margin: 2rem auto; padding: 0 1rem; }
.chat-card { background: #fff; border-radius: 12px; box-shadow: 0 2px 12px rgba(0,0,0,.08); overflow: hidden; }
.chat-messages { padding: 1.5rem; min-height: 280px; max-height: 420px; overflow-y: auto; display: flex; flex-direction: column; gap: 1rem; }
.msg { max-width: 78%; padding: 0.65rem 1rem; border-radius: 18px; font-size: 0.93rem; line-height: 1.5; }
.msg-bot { background: #f0f4f8; color: #1e3a5f; align-self: flex-start; border-bottom-left-radius: 4px; }
.msg-user { background: #1e3a5f; color: #fff; align-self: flex-end; border-bottom-right-radius: 4px; }
.msg-link { display: inline-block; margin-top: 0.5rem; background: #fff; color: #1e3a5f; padding: 0.4rem 0.9rem; border-radius: 20px; text-decoration: none; font-weight: 600; font-size: 0.85rem; border: 1px solid #1e3a5f; }
.msg-link:hover { background: #1e3a5f; color: #fff; }
.chat-form { border-top: 1px solid #e8edf2; padding: 1rem; background: #fafbfc; }
.name-row { display: flex; gap: 0.5rem; margin-bottom: 0.6rem; }
.name-row input { flex: 1; padding: 0.5rem 0.75rem; border: 1px solid #d0d7df; border-radius: 8px; font-size: 0.9rem; }
.input-row { display: flex; gap: 0.5rem; }
.input-row textarea { flex: 1; padding: 0.55rem 0.75rem; border: 1px solid #d0d7df; border-radius: 8px; font-size: 0.9rem; resize: none; font-family: inherit; }
.input-row button { background: #1e3a5f; color: #fff; border: none; border-radius: 8px; padding: 0 1.1rem; cursor: pointer; font-size: 1.1rem; }
.input-row button:hover { background: #16304f; }
.hint { font-size: 0.78rem; color: #8896a5; margin-top: 0.5rem; }
.provenance-note { margin-top: 1.25rem; background: #e8f4fd; border: 1px solid #b8d9f0; border-radius: 8px; padding: 0.85rem 1rem; font-size: 0.82rem; color: #1e3a5f; }
.provenance-note strong { display: block; margin-bottom: 0.2rem; }
</style>
</head>
<body>
<header>
  <div class="header-inner">
    <span class="logo">🔧</span>
    <div>
      <h1>Ace Plumbing Co.</h1>
      <p>Licensed &amp; Insured · ace-plumbing.example</p>
    </div>
  </div>
  <nav><a href="/verify">Verify a Quote</a></nav>
</header>

<div class="chat-wrap">
  <div class="chat-card">
    <div class="chat-messages" id="messages">
      <div class="msg msg-bot">Hi! I'm the Ace Plumbing estimator. Tell me what's going on and I'll put together a quote for you.<br><br>Try: <em>"my kitchen faucet is dripping"</em> or <em>"burst pipe in the bathroom"</em></div>
    </div>
    <div class="chat-form">
      <div class="name-row">
        <input type="text" id="customer" placeholder="Your name (optional)">
      </div>
      <div class="input-row">
        <textarea id="message" rows="2" placeholder="Describe your plumbing problem…"></textarea>
        <button onclick="sendMessage()" title="Send">&#9658;</button>
      </div>
      <p class="hint">Press Enter or click ▶ to get an estimate.</p>
    </div>
  </div>
  <div class="provenance-note">
    <strong>🔐 DNSid-signed quotes</strong>
    Every quote is signed with an Ed25519 key anchored to <code>ace-plumbing.example</code>. Anyone can verify authenticity on the <a href="/verify">Verify</a> page — no account needed.
  </div>
</div>

<script>
const messagesEl = document.getElementById('messages');
const customerEl = document.getElementById('customer');
const messageEl  = document.getElementById('message');

messageEl.addEventListener('keydown', function(e) {
  if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); }
});

function addMsg(text, type, linkURL, linkText) {
  const div = document.createElement('div');
  div.className = 'msg msg-' + type;
  div.textContent = text;
  if (linkURL) {
    const a = document.createElement('a');
    a.className = 'msg-link';
    a.href = linkURL;
    a.textContent = linkText || 'View Quote';
    div.appendChild(document.createElement('br'));
    div.appendChild(a);
  }
  messagesEl.appendChild(div);
  messagesEl.scrollTop = messagesEl.scrollHeight;
}

async function sendMessage() {
  const customer = customerEl.value.trim();
  const message  = messageEl.value.trim();
  if (!message) return;

  addMsg(message, 'user');
  messageEl.value = '';

  const res = await fetch('/chat', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({customer: customer, message: message})
  });
  const data = await res.json();
  addMsg(data.reply, 'bot', data.quote_url, 'View Signed Quote →');
}
</script>
</body>
</html>`

const quoteTmpl = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Quote {{.ID}} · Ace Plumbing Co.</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #f0f4f8; }
.page { max-width: 720px; margin: 2rem auto; padding: 0 1rem; }
.doc { background: #fff; border-radius: 12px; box-shadow: 0 2px 12px rgba(0,0,0,.08); overflow: hidden; }
.doc-header { background: #1e3a5f; color: #fff; padding: 2rem 2.5rem; }
.doc-header h1 { font-size: 1.5rem; font-weight: 700; }
.doc-header .meta { margin-top: 0.5rem; font-size: 0.85rem; opacity: 0.8; }
.doc-body { padding: 2rem 2.5rem; }
.section { margin-bottom: 1.75rem; }
.section h2 { font-size: 0.7rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.08em; color: #8896a5; margin-bottom: 0.75rem; }
.customer-info { display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem; font-size: 0.92rem; }
.customer-info dt { color: #8896a5; }
.customer-info dd { font-weight: 500; }
.problem-box { background: #f7f9fb; border-radius: 8px; padding: 0.75rem 1rem; font-size: 0.92rem; color: #334; font-style: italic; }
table { width: 100%; border-collapse: collapse; font-size: 0.92rem; }
th { text-align: left; padding: 0.5rem 0.75rem; border-bottom: 2px solid #e8edf2; color: #8896a5; font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.05em; }
td { padding: 0.65rem 0.75rem; border-bottom: 1px solid #f0f4f8; }
.price-col { text-align: right; font-variant-numeric: tabular-nums; }
.total-row td { font-weight: 700; font-size: 1.05rem; border-top: 2px solid #1e3a5f; border-bottom: none; padding-top: 0.85rem; }
.jwt-section { background: #f7f9fb; border: 1px solid #e0e8ef; border-radius: 10px; padding: 1.25rem 1.5rem; }
.jwt-section h2 { font-size: 0.7rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.08em; color: #8896a5; margin-bottom: 0.6rem; }
.jwt-section p { font-size: 0.83rem; color: #556; margin-bottom: 0.75rem; line-height: 1.5; }
.jwt-token { font-family: "SFMono-Regular", Consolas, monospace; font-size: 0.72rem; word-break: break-all; background: #fff; border: 1px solid #dce4ec; border-radius: 6px; padding: 0.75rem; color: #334; max-height: 90px; overflow-y: auto; }
.jwt-actions { margin-top: 0.75rem; display: flex; gap: 0.5rem; flex-wrap: wrap; }
.btn { display: inline-block; padding: 0.45rem 1rem; border-radius: 6px; font-size: 0.83rem; font-weight: 600; cursor: pointer; border: none; text-decoration: none; }
.btn-primary { background: #1e3a5f; color: #fff; }
.btn-primary:hover { background: #16304f; }
.btn-outline { background: transparent; color: #1e3a5f; border: 1px solid #1e3a5f; }
.btn-outline:hover { background: #1e3a5f; color: #fff; }
.footer { margin-top: 1.5rem; font-size: 0.78rem; color: #8896a5; text-align: center; }
.badge { display: inline-flex; align-items: center; gap: 0.3rem; background: #e7f5ec; color: #217a45; border: 1px solid #b2dfc2; border-radius: 20px; padding: 0.3rem 0.75rem; font-size: 0.8rem; font-weight: 600; }
@media print {
  body { background: #fff; }
  .page { margin: 0; padding: 0; }
  .doc { box-shadow: none; border-radius: 0; }
  .jwt-actions, .footer { display: none; }
}
</style>
</head>
<body>
<div class="page">
  <div class="doc">
    <div class="doc-header">
      <h1>🔧 Ace Plumbing Co. — Estimate</h1>
      <div class="meta">Quote {{.ID}} &nbsp;·&nbsp; {{fmtTime .CreatedAt}} &nbsp;·&nbsp; ace-plumbing.example</div>
    </div>
    <div class="doc-body">

      <div class="section">
        <h2>Customer</h2>
        <dl class="customer-info">
          <dt>Name</dt><dd>{{.CustomerName}}</dd>
          <dt>Quote ID</dt><dd>{{.ID}}</dd>
        </dl>
      </div>

      <div class="section">
        <h2>Problem Reported</h2>
        <div class="problem-box">&#8220;{{.Problem}}&#8221;</div>
      </div>

      <div class="section">
        <h2>Estimate Breakdown</h2>
        <table>
          <thead><tr><th>Description</th><th class="price-col">Amount</th></tr></thead>
          <tbody>
            {{range .Items}}
            <tr><td>{{.Description}}</td><td class="price-col">{{currency .Price}}</td></tr>
            {{end}}
          </tbody>
          <tfoot>
            <tr class="total-row"><td>Total Estimate</td><td class="price-col">{{currency .Total}}</td></tr>
          </tfoot>
        </table>
      </div>

      <div class="jwt-section section">
        <h2>DNSid Provenance Token</h2>
        <p>
          This quote is signed with an Ed25519 key anchored to <strong>ace-plumbing.example</strong> via a
          <code>_dnsid</code> TXT record. The JWT below encodes the quote ID, customer, and amount.
          Anyone can verify it hasn't been altered — no login required.
        </p>
        <span class="badge">🔐 Signed · EdDSA (Ed25519)</span>
        <div style="margin-top:0.75rem" class="jwt-token" id="jwt-token">{{.JWT}}</div>
        <div class="jwt-actions">
          <button class="btn btn-outline" onclick="copyJWT()">Copy JWT</button>
          <a class="btn btn-primary" href="/verify">Verify this JWT →</a>
          <button class="btn btn-outline" onclick="window.print()">Print / Save as PDF</button>
        </div>
      </div>

    </div>
  </div>
  <div class="footer">Estimate valid 30 days · Ace Plumbing Co. · Licensed &amp; Insured</div>
</div>

<script>
function copyJWT() {
  const jwt = document.getElementById('jwt-token').textContent.trim();
  navigator.clipboard.writeText(jwt).then(function() {
    alert('JWT copied to clipboard!');
  });
}
</script>
</body>
</html>`

const verifyTmpl = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Verify Quote · Ace Plumbing Co.</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #f0f4f8; min-height: 100vh; }
header { background: #1e3a5f; color: #fff; padding: 1rem 1.5rem; display: flex; align-items: center; gap: 0.75rem; }
header h1 { font-size: 1.25rem; font-weight: 600; }
nav a { color: #a8d0f0; font-size: 0.85rem; text-decoration: none; margin-left: auto; }
nav a:hover { color: #fff; }
.page { max-width: 680px; margin: 2rem auto; padding: 0 1rem; }
.card { background: #fff; border-radius: 12px; box-shadow: 0 2px 12px rgba(0,0,0,.08); padding: 2rem; }
.card h2 { font-size: 1.1rem; font-weight: 700; color: #1e3a5f; margin-bottom: 0.4rem; }
.card p { font-size: 0.88rem; color: #556; line-height: 1.55; margin-bottom: 1.25rem; }
textarea { width: 100%; height: 120px; font-family: "SFMono-Regular", Consolas, monospace; font-size: 0.78rem; border: 1px solid #d0d7df; border-radius: 8px; padding: 0.75rem; resize: vertical; }
button[type=submit] { margin-top: 0.75rem; background: #1e3a5f; color: #fff; border: none; border-radius: 8px; padding: 0.6rem 1.5rem; font-size: 0.9rem; font-weight: 600; cursor: pointer; }
button[type=submit]:hover { background: #16304f; }
.result { margin-top: 1.5rem; border-radius: 10px; padding: 1.25rem 1.5rem; display: none; }
.result.valid   { background: #e7f5ec; border: 1px solid #b2dfc2; }
.result.invalid { background: #fdf0f0; border: 1px solid #f0b8b8; }
.result-header { display: flex; align-items: center; gap: 0.6rem; font-size: 1.05rem; font-weight: 700; margin-bottom: 0.75rem; }
.result.valid   .result-header { color: #1a6b38; }
.result.invalid .result-header { color: #b22222; }
.steps { list-style: none; font-size: 0.83rem; margin-bottom: 1rem; line-height: 1.8; font-family: "SFMono-Regular", Consolas, monospace; }
.steps li { padding: 0.1rem 0; }
.claims { background: #fff; border: 1px solid #dce4ec; border-radius: 6px; padding: 0.75rem 1rem; font-size: 0.82rem; font-family: "SFMono-Regular", Consolas, monospace; word-break: break-all; white-space: pre-wrap; color: #334; margin-top: 0.5rem; }
.how { margin-top: 1.5rem; background: #f7f9fb; border: 1px solid #e0e8ef; border-radius: 10px; padding: 1.25rem 1.5rem; font-size: 0.83rem; color: #446; line-height: 1.65; }
.how h3 { font-size: 0.78rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.07em; color: #8896a5; margin-bottom: 0.6rem; }
.how ol { padding-left: 1.25rem; }
.how li { margin-bottom: 0.35rem; }
.how code { background: #e8edf2; padding: 0.1rem 0.35rem; border-radius: 3px; font-size: 0.8rem; }
</style>
</head>
<body>
<header>
  <span style="font-size:1.6rem">🔧</span>
  <h1>Ace Plumbing Co. — Quote Verifier</h1>
  <nav><a href="/">← Back to chat</a></nav>
</header>

<div class="page">
  <div class="card">
    <h2>Verify a signed quote JWT</h2>
    <p>Paste the provenance token from any Ace Plumbing quote. The verifier resolves
    the issuer's <code>_dnsid</code> TXT record, fetches its JWKS, and checks the
    Ed25519 signature — fully independent of the quote document itself.</p>

    <form id="verify-form">
      <textarea id="jwt-input" placeholder="Paste JWT here…" spellcheck="false"></textarea>
      <button type="submit">Verify →</button>
    </form>

    <div class="result" id="result">
      <div class="result-header" id="result-header"></div>
      <ul class="steps" id="result-steps"></ul>
      <div class="claims" id="result-claims" style="display:none"></div>
    </div>

    <div class="how">
      <h3>How verification works</h3>
      <ol>
        <li>Parse the JWT and extract the <code>iss</code> claim (the issuer domain).</li>
        <li>Resolve <code>_dnsid.&lt;issuer&gt;</code> TXT record — this is the DNS anchor. The record's <code>ku=</code> field points to the issuer's JWKS.</li>
        <li>Fetch the JWKS and find the key matching the JWT's <code>kid</code>.</li>
        <li>Verify the <strong>EdDSA (Ed25519)</strong> signature over <code>header.payload</code>.</li>
        <li>Validate <code>exp</code> — the token must not be expired.</li>
      </ol>
      <p style="margin-top:0.75rem;font-style:italic;color:#8896a5">
        (This demo uses a mock DNS map instead of a live DNS lookup, but the logic is identical.)
      </p>
    </div>
  </div>
</div>

<script>
document.getElementById('verify-form').addEventListener('submit', async function(e) {
  e.preventDefault();
  const token = document.getElementById('jwt-input').value.trim();
  if (!token) return;

  const resultEl  = document.getElementById('result');
  const headerEl  = document.getElementById('result-header');
  const stepsEl   = document.getElementById('result-steps');
  const claimsEl  = document.getElementById('result-claims');

  resultEl.style.display = 'none';
  stepsEl.innerHTML = '';
  claimsEl.style.display = 'none';

  const res  = await fetch('/api/verify', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({token: token})
  });
  const data = await res.json();

  resultEl.className = 'result ' + (data.valid ? 'valid' : 'invalid');
  headerEl.textContent = data.valid ? '✅ Signature valid' : '❌ Verification failed';
  if (!data.valid && data.error) {
    headerEl.textContent += ' — ' + data.error;
  }

  (data.steps || []).forEach(function(s) {
    const li = document.createElement('li');
    li.textContent = s;
    stepsEl.appendChild(li);
  });

  if (data.valid && data.claims) {
    const pretty = JSON.stringify(data.claims, null, 2);
    claimsEl.textContent = pretty;
    claimsEl.style.display = 'block';
  }

  resultEl.style.display = 'block';
});
</script>
</body>
</html>`
