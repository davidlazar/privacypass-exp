package main

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cloudflare/pat-go/tokens/type2"
	"github.com/cloudflare/pat-go/util"
	"golang.org/x/oauth2"
)

type server struct {
	key          *rsa.PrivateKey
	oauth        *oauth2.Config
	userInfoURL  string
	walletURL    string      // where login sends the user back to
	walletOrigin string      // the only origin whose pages may call the wallet's endpoints
	sealer       cipher.AEAD // for seal and open

	mu       sync.Mutex
	sessions map[string]session // keyed by session ID
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func mustGetenv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		fatal("required environment variable not set", "var", key)
	}
	return v
}

// allowWallet lets pages on the wallet's origin read h's responses (CORS).
func (s *server) allowWallet(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", s.walletOrigin)
		h(w, r)
	}
}

// handlePreflight answers the CORS preflight a browser sends before a wallet
// request that has an Authorization header.
func (s *server) handlePreflight(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", s.walletOrigin)
	w.Header().Set("Access-Control-Allow-Headers", "Authorization")
	w.WriteHeader(http.StatusNoContent)
}

// handleWallet serves the client page that obtains a token from /token.
func (s *server) handleWallet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(walletPage)
}

// handleSnippet serves privacypass.js, which origins embed on their pages to
// get tokens from the wallet. The script finds the wallet relative to its own
// URL, so it's served next to it.
func (s *server) handleSnippet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Write(snippet)
}

// handleDirectory serves the issuer directory (RFC 9578, section 4), where
// clients and origins find the issuer's token key.
func (s *server) handleDirectory(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/private-token-issuer-directory")
	// The key changes only when the issuer restarts with a new key file.
	w.Header().Set("Cache-Control", "max-age=3600")
	// It's public, so pages on any origin may read it.
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Write(directory)
}

// maxTokenBatch is the most tokens a client can ask for in one /token request.
const maxTokenBatch = 100

// maxTokenRequestBytes bounds the /token request body. Each request in a batch
// carries a 256-byte blinded message: about 350 bytes as base64, or 1 KiB as a
// JSON array of numbers.
const maxTokenRequestBytes = maxTokenBatch * (2 << 10)

// handleTokenRequest signs a batch of blinded token requests. The body is a
// JSON array of requests. The response is a JSON object whose BlindSignatures
// array has one base64 blind signature per request, in the same order.
func (s *server) handleTokenRequest(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.currentSession(r); !ok {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "login required", http.StatusUnauthorized)
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxTokenRequestBytes))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// Values rather than pointers, so a null in the array can't become a nil
	// request.
	var reqs []type2.BasicPublicTokenRequest
	if err := json.Unmarshal(body, &reqs); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if len(reqs) == 0 || len(reqs) > maxTokenBatch {
		http.Error(w, fmt.Sprintf("a batch must have 1 to %d token requests", maxTokenBatch), http.StatusBadRequest)
		return
	}

	issuer := type2.NewBasicPublicIssuer(s.key)
	keyID := issuer.TokenKeyID()
	// Check the whole batch before signing anything, so a bad batch is
	// rejected without spending any signing work.
	for i, req := range reqs {
		// A request names the key it was made for by the last byte of its key ID.
		if req.TokenKeyID != keyID[len(keyID)-1] {
			http.Error(w, fmt.Sprintf("request %d: unknown token key", i), http.StatusBadRequest)
			return
		}
		// The blinded message must be a valid RSA input for our key: exactly
		// the modulus size and less than the modulus (RFC 9474). Checking here
		// keeps a bad request from surfacing as a signing failure below.
		if len(req.BlindedReq) != s.key.Size() || new(big.Int).SetBytes(req.BlindedReq).Cmp(s.key.N) >= 0 {
			http.Error(w, fmt.Sprintf("request %d: invalid blinded message", i), http.StatusBadRequest)
			return
		}
	}

	var resp struct {
		BlindSignatures [][]byte
	}
	resp.BlindSignatures = make([][]byte, len(reqs))
	for i := range reqs {
		blindSig, err := issuer.Evaluate(&reqs[i])
		if err != nil {
			// The input was validated above, so this is a failure on our side.
			slog.Error("evaluate token request", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		resp.BlindSignatures[i] = blindSig
	}

	data, err := json.Marshal(resp)
	if err != nil {
		slog.Error("encode token response", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Write(data)
}

// Token type 2 (RFC 9578) is defined for 2048-bit RSA keys.
const issuerKeyBits = 2048

// loadOrCreateKey reads a PEM-encoded PKCS #8 RSA private key from path. If
// the file doesn't exist, it generates a new key and saves it there.
func loadOrCreateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return createKey(path)
	}
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%s: no PEM data found", path)
	}
	if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("%s: PEM block is %q, want \"PRIVATE KEY\" (PKCS #8)", path, block.Type)
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	key, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s: not an RSA key", path)
	}
	if n := key.N.BitLen(); n != issuerKeyBits {
		return nil, fmt.Errorf("%s: RSA key is %d bits, want %d", path, n, issuerKeyBits)
	}
	return key, nil
}

func createKey(path string) (*rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, issuerKeyBits)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}

	// O_EXCL so we never clobber a key that appeared after the read above.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	err = pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(path) // don't leave a truncated key behind for the next start
		return nil, fmt.Errorf("write %s: %w", path, err)
	}
	slog.Info("generated new issuer key", "path", path)
	return key, nil
}

var keyPath = flag.String("key", "issuer-key.pem", "path to the issuer's RSA private key (PEM, PKCS #8); generated if it doesn't exist")

// walletPage is wallet.html, rendered once at startup in main. snippet is
// privacypass.js, and directory the issuer directory, also made at startup.
var walletPage, snippet, directory []byte

// fatal logs msg at error level and exits.
func fatal(msg string, args ...any) {
	slog.Error(msg, args...)
	os.Exit(1)
}

func main() {
	flag.Parse()

	// Where users reach this server, which can differ from where it listens
	// (ADDR), behind a proxy say. This server is the issuer, so its host is the
	// issuer name that goes in token challenges.
	baseURL := getenv("BASE_URL", "http://localhost:8080")
	base, err := url.Parse(baseURL)
	if err != nil || base.Host == "" {
		fatal("invalid BASE_URL", "url", baseURL)
	}
	issuerName := base.Host
	issuerURL := base.Scheme + "://" + base.Host
	// Register this with the OAuth provider.
	redirectURL := issuerURL + "/callback"

	addr := getenv("ADDR", ":8080")

	// The wallet page, which login sends the user back to. Its origin is the
	// only one whose pages may call /session, /token, /logout and /me. By
	// default it's the one this server serves.
	walletURL := getenv("WALLET_URL", issuerURL+"/wallet")
	wallet, err := url.Parse(walletURL)
	if err != nil {
		fatal("invalid WALLET_URL", "url", walletURL)
	}

	clientID := mustGetenv("OAUTH_CLIENT_ID")
	clientSecret := mustGetenv("OAUTH_CLIENT_SECRET")

	// The OAuth provider's endpoints, and the scopes to request: space-separated,
	// as in OAuth's scope parameter, and none by default.
	endpoint := oauth2.Endpoint{
		AuthURL:  mustGetenv("OAUTH_AUTH_URL"),
		TokenURL: mustGetenv("OAUTH_TOKEN_URL"),
	}
	userInfoURL := mustGetenv("OAUTH_USERINFO_URL")
	scopes := strings.Fields(os.Getenv("OAUTH_SCOPES"))

	privateKey, err := loadOrCreateKey(*keyPath)
	if err != nil {
		fatal("load issuer key", "err", err)
	}
	// The token key in RFC 9578's encoding (SPKI with the RSASSA-PSS OID).
	// Clients and origins derive the token key ID by hashing these exact bytes.
	publicKeyBytes, err := util.MarshalTokenKeyPSSOID(&privateKey.PublicKey)
	if err != nil {
		panic(err)
	}
	slog.Info("issuer key ready", "path", *keyPath, "token_key", base64.StdEncoding.EncodeToString(publicKeyBytes))

	// RFC 9578 encodes the key as base64url with padding. The request URI is
	// /token, though /token takes this issuer's JSON batches, not RFC 9578's
	// binary token requests.
	directory, err = json.Marshal(map[string]any{
		"issuer-request-uri": issuerURL + "/token",
		"token-keys": []map[string]any{{
			"token-type": type2.BasicPublicTokenType,
			"token-key":  base64.URLEncoding.EncodeToString(publicKeyBytes),
		}},
	})
	if err != nil {
		panic(err)
	}

	snippet, err = os.ReadFile("privacypass.js")
	if err != nil {
		fatal("read privacypass.js", "err", err)
	}

	walletTmpl, err := template.ParseFiles("wallet.html")
	if err != nil {
		fatal("parse wallet template", "err", err)
	}
	var buf bytes.Buffer
	// html/template quotes and escapes these strings for the JS context.
	err = walletTmpl.Execute(&buf, struct {
		IssuerURL  string
		IssuerName string
		PublicKey  string // base64
	}{
		IssuerURL:  issuerURL,
		IssuerName: issuerName,
		PublicKey:  base64.StdEncoding.EncodeToString(publicKeyBytes),
	})
	if err != nil {
		fatal("render wallet template", "err", err)
	}
	walletPage = buf.Bytes()

	s := &server{
		key: privateKey,
		oauth: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint:     endpoint,
			RedirectURL:  redirectURL,
			Scopes:       scopes,
		},
		userInfoURL:  userInfoURL,
		walletURL:    walletURL,
		walletOrigin: wallet.Scheme + "://" + wallet.Host,
		sealer:       newSealer(),
		sessions:     make(map[string]session),
	}
	go s.expireSessions(10 * time.Minute)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", s.handleLogin)
	mux.HandleFunc("GET /wallet", s.handleWallet)
	mux.HandleFunc("GET /privacypass.js", s.handleSnippet)
	mux.HandleFunc("GET /.well-known/private-token-issuer-directory", s.handleDirectory)
	mux.HandleFunc("GET /callback", s.handleCallback)
	// The wallet calls these from its own origin.
	for pattern, h := range map[string]http.HandlerFunc{
		"POST /session": s.handleSession,
		"POST /token":   s.handleTokenRequest,
		"POST /logout":  s.handleLogout,
		"GET /me":       s.handleMe,
	} {
		mux.HandleFunc(pattern, s.allowWallet(h))
		_, path, _ := strings.Cut(pattern, " ")
		mux.HandleFunc("OPTIONS "+path, s.handlePreflight)
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	slog.Info("listening", "addr", addr, "callback", redirectURL, "issuer_name", issuerName, "wallet", walletURL)
	fatal("server stopped", "err", srv.ListenAndServe())
}
