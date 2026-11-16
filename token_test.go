package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cloudflare/pat-go/tokens"
	"github.com/cloudflare/pat-go/tokens/type2"
	"github.com/cloudflare/pat-go/util"

	"privacypass/verify"
)

const testSessionID = "test-session"

// newTestIssuer starts the /token handler for a fresh issuer key with a
// logged-in session (testSessionID). It returns the server and the token key
// as the issuer publishes it.
func newTestIssuer(t *testing.T) (*httptest.Server, []byte) {
	t.Helper()
	key := generateIssuerKey(t)
	s := &server{
		key: key,
		sessions: map[string]session{
			testSessionID: {expires: time.Now().Add(time.Hour)},
		},
	}
	srv := httptest.NewServer(http.HandlerFunc(s.handleTokenRequest))
	t.Cleanup(srv.Close)
	tokenKey, err := util.MarshalTokenKeyPSSOID(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return srv, tokenKey
}

// The challenge wallet.html uses: empty redemption context, no origin info.
var testChallenge = tokens.TokenChallenge{
	TokenType:  type2.BasicPublicTokenType,
	IssuerName: "issuer.example",
}.Marshal()

// TestTokenVerifies gets a batch of tokens from the /token handler the way a
// client would, and checks that an origin can verify each with
// verify.PublicToken.
func TestTokenVerifies(t *testing.T) {
	srv, tokenKey := newTestIssuer(t)

	toks := requestTokens(t, srv, testChallenge, tokenKey, 3)
	for i, token := range toks {
		if err := verify.PublicToken(token, testChallenge, tokenKey); err != nil {
			t.Errorf("token %d: verify.PublicToken rejected a token from the server: %v", i, err)
		}
	}

	// A token must stop verifying if anything it's bound to changes.
	token := toks[0]
	tampered := bytes.Clone(token)
	tampered[len(tampered)-1] ^= 1 // the authenticator is last
	trailing := append(bytes.Clone(token), 0)
	otherChallenge := tokens.TokenChallenge{
		TokenType:  type2.BasicPublicTokenType,
		IssuerName: "other.example",
	}.Marshal()
	otherKey, err := util.MarshalTokenKeyPSSOID(&generateIssuerKey(t).PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name                       string
		token, challenge, tokenKey []byte
	}{
		{"tampered token", tampered, testChallenge, tokenKey},
		{"trailing byte", trailing, testChallenge, tokenKey},
		{"other challenge", token, otherChallenge, tokenKey},
		{"other issuer key", token, testChallenge, otherKey},
	} {
		if err := verify.PublicToken(tc.token, tc.challenge, tc.tokenKey); err == nil {
			t.Errorf("%s: verify.PublicToken accepted the token", tc.name)
		}
	}
}

// TestTokenBatch checks which batches /token accepts.
func TestTokenBatch(t *testing.T) {
	srv, tokenKey := newTestIssuer(t)
	reqs := func(n int) []*type2.BasicPublicTokenRequest {
		var rs []*type2.BasicPublicTokenRequest
		for _, st := range newTokenRequests(t, testChallenge, tokenKey, n) {
			rs = append(rs, st.Request())
		}
		return rs
	}
	jsonOf := func(v any) []byte {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	// One good request and one whose blinded message is cut short.
	oneBad := reqs(2)
	oneBad[1].BlindedReq = oneBad[1].BlindedReq[:100]
	// The bytes encoded as JSON arrays of numbers, as wallet.html used to send
	// them: the largest encoding the body limit allows for.
	var numberArrays []map[string]any
	for _, r := range reqs(maxTokenBatch) {
		nums := make([]int, len(r.BlindedReq))
		for i, b := range r.BlindedReq {
			nums[i] = int(b)
		}
		numberArrays = append(numberArrays, map[string]any{"BlindedReq": nums, "TokenKeyId": r.TokenKeyID})
	}

	for _, tc := range []struct {
		name     string
		body     []byte
		want     int
		wantSigs int
	}{
		{"single request, not in an array", jsonOf(reqs(1)[0]), http.StatusBadRequest, 0},
		{"empty batch", []byte(`[]`), http.StatusBadRequest, 0},
		{"null entry", []byte(`[null]`), http.StatusBadRequest, 0},
		{"one bad request", jsonOf(oneBad), http.StatusBadRequest, 0},
		{"too many requests", jsonOf(reqs(maxTokenBatch + 1)), http.StatusBadRequest, 0},
		{"batch of one", jsonOf(reqs(1)), http.StatusOK, 1},
		{"full batch", jsonOf(reqs(maxTokenBatch)), http.StatusOK, maxTokenBatch},
		{"full batch, bytes as number arrays", jsonOf(numberArrays), http.StatusOK, maxTokenBatch},
	} {
		resp := postTokenRequests(t, srv, tc.body)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != tc.want {
			t.Errorf("%s (%d-byte body): got %s %q, want %d", tc.name, len(tc.body), resp.Status, bytes.TrimSpace(body), tc.want)
			continue
		}
		if tc.want != http.StatusOK {
			continue
		}
		var tokResp struct{ BlindSignatures [][]byte }
		if err := json.Unmarshal(body, &tokResp); err != nil {
			t.Errorf("%s: decode response: %v", tc.name, err)
		} else if len(tokResp.BlindSignatures) != tc.wantSigs {
			t.Errorf("%s: got %d signatures, want %d", tc.name, len(tokResp.BlindSignatures), tc.wantSigs)
		}
	}
}

// newTokenRequests makes n blinded token requests for challenge the way a
// client does, working only from the published token key.
func newTokenRequests(t *testing.T, challenge, tokenKey []byte, n int) []type2.BasicPublicTokenRequestState {
	t.Helper()
	pub, err := util.UnmarshalTokenKey(tokenKey)
	if err != nil {
		t.Fatal(err)
	}
	keyID := sha256.Sum256(tokenKey)
	states := make([]type2.BasicPublicTokenRequestState, n)
	for i := range states {
		nonce := make([]byte, 32)
		rand.Read(nonce)
		states[i], err = type2.NewBasicPublicClient().CreateTokenRequest(challenge, nonce, keyID[:], pub)
		if err != nil {
			t.Fatal(err)
		}
	}
	return states
}

// requestTokens does what a client does to get n tokens for challenge: makes
// the blinded token requests, POSTs them as a batch to the issuer's /token
// endpoint, and unblinds the responses. It returns the serialized tokens.
func requestTokens(t *testing.T, srv *httptest.Server, challenge, tokenKey []byte, n int) [][]byte {
	t.Helper()
	states := newTokenRequests(t, challenge, tokenKey, n)
	reqs := make([]*type2.BasicPublicTokenRequest, n)
	for i, st := range states {
		reqs[i] = st.Request()
	}
	body, err := json.Marshal(reqs)
	if err != nil {
		t.Fatal(err)
	}

	resp := postTokenRequests(t, srv, body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST /token: %s: %s", resp.Status, msg)
	}
	var tokResp struct{ BlindSignatures [][]byte }
	if err := json.NewDecoder(resp.Body).Decode(&tokResp); err != nil {
		t.Fatalf("decode /token response: %v", err)
	}
	sigs := tokResp.BlindSignatures
	if len(sigs) != n {
		t.Fatalf("asked for %d tokens, got %d signatures", n, len(sigs))
	}

	toks := make([][]byte, n)
	for i, st := range states {
		tok, err := st.FinalizeToken(sigs[i])
		if err != nil {
			t.Fatalf("finalize token %d: %v", i, err)
		}
		toks[i] = tok.Marshal()
	}
	return toks
}

// postTokenRequests POSTs body to the issuer's /token endpoint with the test
// session's ID as a bearer token.
func postTokenRequests(t *testing.T, srv *httptest.Server, body []byte) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/token", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+testSessionID)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func generateIssuerKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, issuerKeyBits)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
