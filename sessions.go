package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

// sessionTTL is how long a login lasts.
const sessionTTL = 24 * time.Hour

// loginTTL is how long the user has to log in at the OAuth provider.
const loginTTL = 10 * time.Minute

// loginCodeTTL is how long the wallet has to trade a login code for a session
// ID. The code passes through the browser's address bar, so it's short-lived.
const loginCodeTTL = time.Minute

type session struct {
	userID  string // the user's ID at the OAuth provider, from fetchUserInfo
	name    string // the user's name, from fetchUserInfo
	expires time.Time
}

// The server doesn't store logins that are still in progress. Instead, the
// OAuth state carries a loginState through the provider, and the login code
// carries a loginCode to the wallet, both sealed by the server.

// A loginState is a login in progress at the OAuth provider.
type loginState struct {
	Verifier  string // our PKCE verifier for the provider
	Challenge string // the wallet's PKCE challenge, which the login code will be bound to
	Expires   time.Time
}

// A loginCode is a finished login that the wallet hasn't traded in yet.
type loginCode struct {
	SessionID string // the session the code starts, chosen when the login finishes
	UserID    string // the user's ID at the OAuth provider, from fetchUserInfo
	Name      string // the user's name, from fetchUserInfo
	Challenge string // the wallet's PKCE challenge
	Expires   time.Time
}

// Purposes for seal, so a sealed value of one kind can't be passed off as
// the other.
const (
	purposeOAuthState  = "oauth state"
	purposeWalletLogin = "login code"
)

// newSealer returns the AEAD that seal uses: AES-256-GCM under a key made
// fresh at each start, so a restart cancels logins in progress, as it ends
// sessions.
func newSealer() cipher.AEAD {
	key := make([]byte, 32)
	rand.Read(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		panic(err)
	}
	return aead
}

// seal encrypts and authenticates v, as JSON, for the browser to carry.
func (s *server) seal(purpose string, v any) string {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(s.sealer.Seal(nil, nil, data, []byte(purpose)))
}

// open decodes into v a value that seal sealed for purpose, and rejects
// anything else.
func (s *server) open(purpose, sealed string, v any) error {
	data, err := base64.RawURLEncoding.DecodeString(sealed)
	if err != nil {
		return err
	}
	data, err = s.sealer.Open(nil, nil, data, []byte(purpose))
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// handleLogin starts the OAuth flow by redirecting to the provider.
//
// The wallet passes code_challenge, the hash of a random verifier it keeps
// (PKCE, RFC 7636, with the S256 method), and has to show the verifier to
// trade the login code at /session. That ties the login code to the browser
// tab that started the login: a code sent to someone else's wallet, or one
// copied out of a URL, is no use without the verifier.
func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	challenge := r.URL.Query().Get("code_challenge")
	if b, err := base64.RawURLEncoding.DecodeString(challenge); err != nil || len(b) != sha256.Size {
		http.Error(w, "missing or invalid code_challenge", http.StatusBadRequest)
		return
	}

	verifier := oauth2.GenerateVerifier()
	state := s.seal(purposeOAuthState, loginState{Verifier: verifier, Challenge: challenge, Expires: time.Now().Add(loginTTL)})
	authURL := s.oauth.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))
	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleCallback is where the provider sends the user back after login. It
// sends the user on to the wallet with a login code, which the wallet trades
// for a session ID at /session.
func (s *server) handleCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	var login loginState
	if err := s.open(purposeOAuthState, q.Get("state"), &login); err != nil || time.Now().After(login.Expires) {
		http.Error(w, "invalid OAuth state; please try logging in again", http.StatusBadRequest)
		return
	}

	if e := q.Get("error"); e != "" {
		http.Error(w, "login failed: "+e, http.StatusUnauthorized)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	token, err := s.oauth.Exchange(ctx, q.Get("code"), oauth2.VerifierOption(login.Verifier))
	if err != nil {
		slog.Error("token exchange", "err", err)
		http.Error(w, "could not complete login", http.StatusBadGateway)
		return
	}

	name, userID, err := s.fetchUserInfo(ctx, token)
	if err != nil {
		slog.Error("fetch user info", "err", err)
		http.Error(w, "could not load your profile", http.StatusBadGateway)
		return
	}

	code := s.seal(purposeWalletLogin, loginCode{
		SessionID: rand.Text(),
		UserID:    userID,
		Name:      name,
		Challenge: login.Challenge,
		Expires:   time.Now().Add(loginCodeTTL),
	})

	// In the fragment, which the browser doesn't send to the wallet's server.
	http.Redirect(w, r, s.walletURL+"#code="+code, http.StatusFound)
}

// handleSession trades a login code from handleCallback for a session ID. The
// body is a form with the code and the code_verifier for the wallet's
// code_challenge. The response is a JSON object with the SessionID, which the
// wallet sends as a bearer token from then on, and the user's Name, which it
// shows without having to ask /me.
//
// The session ID comes from the code, so trading the same code again gives
// the same session rather than adding another. Unlike an OAuth authorization
// server (RFC 6749, section 4.1.2), we don't reject a reused code: that would
// mean storing used codes, and a reused code needs the verifier anyway, which
// the wallet deletes once it has its session.
//
// A catch: trading a code again also brings back its session if it was logged
// out in the code's first minute. Only someone holding the verifier could do
// that. Closing it would mean remembering logged-out session IDs until their
// codes expire.
func (s *server) handleSession(w http.ResponseWriter, r *http.Request) {
	// The code holds the user's name and ID, so allow for long ones.
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var login loginCode
	err := s.open(purposeWalletLogin, r.PostForm.Get("code"), &login)
	if err != nil || time.Now().After(login.Expires) ||
		oauth2.S256ChallengeFromVerifier(r.PostForm.Get("code_verifier")) != login.Challenge {
		http.Error(w, "invalid or expired login code; please try logging in again", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	s.sessions[login.SessionID] = session{userID: login.UserID, name: login.Name, expires: time.Now().Add(sessionTTL)}
	s.mu.Unlock()
	json.NewEncoder(w).Encode(struct{ SessionID, Name string }{login.SessionID, login.Name})
}

// handleLogout ends the session whose ID the request carries as a bearer
// token. (See handleSession for how a session can come back in its first
// minute.)
func (s *server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	delete(s.sessions, bearerToken(r))
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

// handleMe reports, as a JSON object with a Name, the name of the user whose
// session ID the request carries as a bearer token.
func (s *server) handleMe(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.currentSession(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "login required", http.StatusUnauthorized)
		return
	}
	json.NewEncoder(w).Encode(struct{ Name string }{sess.name})
}

// fetchUserInfo calls the provider's user-info endpoint and returns the
// user's display name and their ID, from the "id" field, or from "sub" for
// OpenID Connect providers that don't send "id". Unlike the name, the ID stays
// the same if the user renames their account.
func (s *server) fetchUserInfo(ctx context.Context, token *oauth2.Token) (name, id string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.userInfoURL, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := s.oauth.Client(ctx, token).Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("user-info endpoint returned %s", resp.Status)
	}

	var info map[string]any
	dec := json.NewDecoder(resp.Body)
	// GitHub's IDs are numbers and Google's are strings. UseNumber keeps a
	// number's digits as sent, rather than making it a float64.
	dec.UseNumber()
	if err := dec.Decode(&info); err != nil {
		return "", "", fmt.Errorf("decode user info: %w", err)
	}
	switch v := info["id"].(type) {
	case string:
		id = v
	case json.Number:
		id = v.String()
	}
	if id == "" {
		id, _ = info["sub"].(string) // always a string in OpenID Connect
	}
	if id == "" {
		return "", "", errors.New("no id or sub in user-info response")
	}
	// GitHub uses "name"/"login", Google uses "name"/"email"; take the first that's set.
	for _, key := range []string{"name", "login", "preferred_username", "email"} {
		if v, ok := info[key].(string); ok && v != "" {
			return v, id, nil
		}
	}
	return "", "", errors.New("no usable name in user-info response")
}

// currentSession returns the session whose ID the request carries as a bearer
// token, and whether it carries a valid one.
func (s *server) currentSession(r *http.Request) (session, bool) {
	sid := bearerToken(r)
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[sid]
	if !ok {
		return session{}, false
	}
	if time.Now().After(sess.expires) {
		delete(s.sessions, sid)
		return session{}, false
	}
	return sess, true
}

// bearerToken returns the token in the request's "Authorization: Bearer"
// header (RFC 6750), or "" if there isn't one.
func bearerToken(r *http.Request) string {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	return token
}

// expireSessions drops expired sessions every interval, so ones that are never
// used again don't pile up. (currentSession rejects expired sessions on its own.)
func (s *server) expireSessions(interval time.Duration) {
	for range time.Tick(interval) {
		s.removeExpiredSessions(time.Now())
	}
}

func (s *server) removeExpiredSessions(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, sess := range s.sessions {
		if now.After(sess.expires) {
			delete(s.sessions, id)
		}
	}
}
