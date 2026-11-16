// Command mockoauth is a minimal OAuth 2.0 provider for running the issuer
// locally without a real one. Its login page accepts any username with the
// password 1234, and its profile endpoint reports that username as the
// user's name and ID. It accepts any client ID, client secret and redirect URI.
//
// Run it from the repository root, and point the issuer at it:
//
//	go run ./demo/mockoauth
//
//	OAUTH_CLIENT_ID=demo OAUTH_CLIENT_SECRET=demo \
//	OAUTH_AUTH_URL=http://localhost:8082/oauth/authorize \
//	OAUTH_TOKEN_URL=http://localhost:8082/oauth/token \
//	OAUTH_USERINFO_URL=http://localhost:8082/api/v1/profiles/me \
//	go run .
//
// ADDR sets where it listens (default :8082).
package main

import (
	"crypto/rand"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
)

const password = "1234"

// The form posts back to the page's own URL, so the authorization request's
// parameters come along in the query string.
var loginPage = template.Must(template.New("login").Parse(`<!DOCTYPE html>
<title>Mock OAuth provider</title>
<h1>Mock OAuth provider</h1>
<p>Log in with any username and the password 1234.</p>
{{if .}}<p><strong>{{.}}</strong></p>{{end}}
<form method="post">
<p><label>Username <input name="username" autofocus></label>
<p><label>Password <input name="password" type="password"></label>
<p><button>Log in</button>
</form>
`))

var (
	mu     sync.Mutex
	codes  = map[string]string{} // authorization code -> username
	tokens = map[string]string{} // access token -> username
)

// redirectURI checks the authorization request's parameters and returns its
// redirect URI.
func redirectURI(w http.ResponseWriter, r *http.Request) (*url.URL, bool) {
	q := r.URL.Query()
	u, err := url.Parse(q.Get("redirect_uri"))
	if err != nil || q.Get("code_challenge") == "" {
		http.Error(w, "bad authorize request", http.StatusBadRequest)
		return nil, false
	}
	return u, true
}

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /oauth/authorize", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := redirectURI(w, r); ok {
			loginPage.Execute(w, "")
		}
	})

	mux.HandleFunc("POST /oauth/authorize", func(w http.ResponseWriter, r *http.Request) {
		u, ok := redirectURI(w, r)
		if !ok {
			return
		}
		username := strings.TrimSpace(r.PostFormValue("username"))
		if username == "" || r.PostFormValue("password") != password {
			log.Printf("login refused for %q", username)
			w.WriteHeader(http.StatusUnauthorized)
			loginPage.Execute(w, "Wrong username or password.")
			return
		}
		code := rand.Text()
		mu.Lock()
		codes[code] = username
		mu.Unlock()
		q := r.URL.Query()
		u.RawQuery = url.Values{"code": {code}, "state": {q.Get("state")}}.Encode()
		log.Printf("authorize client_id=%s scope=%q user=%q", q.Get("client_id"), q.Get("scope"), username)
		http.Redirect(w, r, u.String(), http.StatusFound)
	})

	mux.HandleFunc("POST /oauth/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		code := r.Form.Get("code")
		mu.Lock()
		username, ok := codes[code]
		delete(codes, code) // a code works once
		mu.Unlock()
		if !ok || r.Form.Get("code_verifier") == "" {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		token := rand.Text()
		mu.Lock()
		tokens[token] = username
		mu.Unlock()
		log.Printf("token exchange ok for %q", username)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"access_token": token, "token_type": "Bearer", "expires_in": 3600})
	})

	mux.HandleFunc("GET /api/v1/profiles/me", func(w http.ResponseWriter, r *http.Request) {
		token, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		mu.Lock()
		username, ok := tokens[token]
		mu.Unlock()
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"id": username, "name": username})
	})

	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = ":8082"
	}
	log.Printf("listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
