// Command origin is a minimal web app where visitors log in with Privacy Pass:
// a token from the issuer stands in for an account, so the app knows the
// visitor got a token but not who they are.
//
// It reads the issuer's token key from the issuer directory at startup, and
// serves a page with a "Login with Privacy Pass" button that uses
// privacypass.js. The button POSTs to /login, which answers with a Privacy
// Pass challenge and then accepts a token for it (RFC 9577).
//
// Run it from the repository root, with the issuer running:
//
//	go run ./demo/origin
//
// Settings, from the environment:
//
//	ISSUER_URL   the issuer (default http://localhost:8080)
//	SNIPPET_URL  privacypass.js, served next to the wallet (default ISSUER_URL/privacypass.js)
//	ADDR         where to listen (default :8081)
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cloudflare/pat-go/tokens"
	"github.com/cloudflare/pat-go/tokens/type2"

	"privacypass/verify"
)

var page = template.Must(template.New("page").Parse(`<!DOCTYPE html>
<title>Demo origin</title>
<h1>Demo origin</h1>
{{if .LoggedIn}}
<p>You're logged in with Privacy Pass.</p>
<form method="post" action="/logout"><button>Log out</button></form>
{{else}}
<button id="login">Login with Privacy Pass</button>
<script src="{{.SnippetURL}}"></script>
<script>
document.getElementById('login').onclick = async () => {
    try {
        const resp = await privacyPassLogin('/login');
        if (!resp.ok) {
            throw new Error(await resp.text());
        }
        location.reload();
    } catch (err) {
        alert('Login failed: ' + err.message);
    }
};
</script>
{{end}}
`))

const sessionCookie = "session"

type origin struct {
	challenge  []byte // the TokenChallenge that tokens must be for
	tokenKey   []byte // the issuer's token key
	authHeader string // the WWW-Authenticate header that asks for a token
	snippetURL string

	mu       sync.Mutex
	spent    map[string]bool // nonces of the tokens redeemed so far
	sessions map[string]bool // IDs of logged-in visitors' sessions
}

func (o *origin) handleIndex(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(sessionCookie)
	o.mu.Lock()
	loggedIn := err == nil && o.sessions[c.Value]
	o.mu.Unlock()
	// So the wallet's host doesn't learn that the user is on this site when
	// the page loads privacypass.js or opens the wallet.
	w.Header().Set("Referrer-Policy", "no-referrer")
	err = page.Execute(w, struct {
		LoggedIn   bool
		SnippetURL string
	}{loggedIn, o.snippetURL})
	if err != nil {
		slog.Error("render page", "err", err)
	}
}

// handleLogin logs the visitor in if the request carries a valid token.
// Otherwise it answers 401 with a challenge for one.
func (o *origin) handleLogin(w http.ResponseWriter, r *http.Request) {
	token, err := privateToken(r)
	if err == nil {
		err = verify.PublicToken(token, o.challenge, o.tokenKey)
	}
	if err == nil && !o.spend(token[2:34]) {
		err = errors.New("token already used")
	}
	if err != nil {
		w.Header().Set("WWW-Authenticate", o.authHeader)
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	sid := rand.Text()
	o.mu.Lock()
	o.sessions[sid] = true
	o.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    sid,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (o *origin) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		o.mu.Lock()
		delete(o.sessions, c.Value)
		o.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// spend records nonce as used and reports whether it was unused, so that
// each token works once. The record only grows, which is fine for a demo; a
// real origin needs it only for as long as the issuer's key is in use.
func (o *origin) spend(nonce []byte) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.spent[string(nonce)] {
		return false
	}
	o.spent[string(nonce)] = true
	return true
}

// privateToken returns the token in the request's
// "Authorization: PrivateToken token=..." header.
func privateToken(r *http.Request) ([]byte, error) {
	scheme, params, _ := strings.Cut(r.Header.Get("Authorization"), " ")
	if !strings.EqualFold(scheme, "PrivateToken") {
		return nil, errors.New("a Privacy Pass token is required")
	}
	for _, param := range strings.Split(params, ",") {
		name, value, _ := strings.Cut(strings.TrimSpace(param), "=")
		if strings.EqualFold(name, "token") {
			return base64.URLEncoding.DecodeString(strings.Trim(value, `"`))
		}
	}
	return nil, errors.New("no token in the Authorization header")
}

// fetchTokenKey gets the issuer's type 2 token key from its directory
// (RFC 9578, section 4).
func fetchTokenKey(issuerURL string) ([]byte, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(issuerURL + "/.well-known/private-token-issuer-directory")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("issuer directory: %s", resp.Status)
	}
	var dir struct {
		TokenKeys []struct {
			TokenType uint16 `json:"token-type"`
			TokenKey  string `json:"token-key"`
		} `json:"token-keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&dir); err != nil {
		return nil, fmt.Errorf("issuer directory: %w", err)
	}
	for _, k := range dir.TokenKeys {
		if k.TokenType == type2.BasicPublicTokenType {
			return base64.URLEncoding.DecodeString(k.TokenKey)
		}
	}
	return nil, errors.New("issuer directory has no type 2 token key")
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	issuerURL := getenv("ISSUER_URL", "http://localhost:8080")
	issuer, err := url.Parse(issuerURL)
	if err != nil {
		slog.Error("invalid ISSUER_URL", "url", issuerURL)
		os.Exit(1)
	}
	tokenKey, err := fetchTokenKey(issuerURL)
	if err != nil {
		slog.Error("get the issuer's token key", "err", err)
		os.Exit(1)
	}

	// The challenge the wallet's tokens are for: the issuer (named by its
	// host), no redemption context and no origin info. So a token works at
	// any origin, and an origin can't tell which visitor it came from.
	challenge := tokens.TokenChallenge{
		TokenType:  type2.BasicPublicTokenType,
		IssuerName: issuer.Host,
	}.Marshal()

	o := &origin{
		challenge: challenge,
		tokenKey:  tokenKey,
		// RFC 9577 encodes both as base64url with padding.
		authHeader: fmt.Sprintf(`PrivateToken challenge="%s", token-key="%s"`,
			base64.URLEncoding.EncodeToString(challenge), base64.URLEncoding.EncodeToString(tokenKey)),
		snippetURL: getenv("SNIPPET_URL", issuerURL+"/privacypass.js"),
		spent:      make(map[string]bool),
		sessions:   make(map[string]bool),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", o.handleIndex)
	mux.HandleFunc("POST /login", o.handleLogin)
	mux.HandleFunc("POST /logout", o.handleLogout)

	addr := getenv("ADDR", ":8081")
	slog.Info("listening", "addr", addr, "issuer", issuerURL, "snippet", o.snippetURL)
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	slog.Error("server stopped", "err", srv.ListenAndServe())
	os.Exit(1)
}
