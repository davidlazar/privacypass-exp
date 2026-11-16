// Package verify is what an origin needs to accept Privacy Pass tokens from
// this issuer.
package verify

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"errors"

	"github.com/cloudflare/pat-go/tokens/type2"
	"github.com/cloudflare/pat-go/util"
)

// PublicToken checks that rawToken is a valid type 2 (publicly verifiable)
// token for challenge, signed with the issuer's token key:
//
//	rawToken:      base64url-decoded value from `Authorization: PrivateToken token=...`
//	challenge:     the exact TokenChallenge bytes you sent in WWW-Authenticate
//	tokenKeyBytes: base64url-decoded "token-key" from the issuer's directory
//
// It doesn't check for replay. Tokens are single-use, so the caller must also
// reject a token whose nonce (rawToken[2:34]) it has already accepted.
func PublicToken(rawToken, challenge, tokenKeyBytes []byte) error {
	pk, err := util.UnmarshalTokenKey(tokenKeyBytes)
	if err != nil {
		return err
	}

	// A type 2 token is token_type (2), nonce (32), challenge_digest (32),
	// token_key_id (32) and authenticator (256) bytes. UnmarshalToken ignores
	// trailing bytes, so check the length here: a token should have exactly
	// one encoding that verifies.
	if len(rawToken) != 2+32+32+32+256 {
		return errors.New("invalid token length")
	}

	token, err := type2.UnmarshalToken(rawToken)
	if err != nil {
		return err
	}

	if token.TokenType != type2.BasicPublicTokenType {
		return errors.New("not a type 2 token")
	}

	// The token commits to the challenge it was issued for by its digest.
	challengeDigest := sha256.Sum256(challenge)
	if !bytes.Equal(token.Context, challengeDigest[:]) {
		return errors.New("token not bound to this challenge")
	}

	keyID := sha256.Sum256(tokenKeyBytes)
	if !bytes.Equal(token.KeyID, keyID[:]) {
		return errors.New("token issued under a different key")
	}

	digest := sha512.Sum384(token.AuthenticatorInput())
	return rsa.VerifyPSS(pk, crypto.SHA384, digest[:], token.Authenticator,
		&rsa.PSSOptions{Hash: crypto.SHA384, SaltLength: crypto.SHA384.Size()})
}
