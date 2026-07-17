package jwt

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Token represents a JWT. Before signing it holds the header and claims to be
// serialized; after parsing it additionally holds the raw compact form and the
// decoded signature.
type Token struct {
	// Raw is the original compact serialization, populated by the parser.
	Raw string
	// Method is the signing method selected from the alg header (or supplied to
	// New).
	Method SigningMethod
	// Header is the decoded JOSE header.
	Header map[string]any
	// Claims is the token payload.
	Claims Claims
	// Signature is the decoded (raw) signature, populated by the parser.
	Signature []byte
	// Valid reports whether the parser considered the token valid.
	Valid bool
}

// New returns a Token that will be signed with method, using RegisteredClaims
// as an empty default payload. Use NewWithClaims to supply claims.
func New(method SigningMethod) *Token {
	return NewWithClaims(method, RegisteredClaims{})
}

// NewWithClaims returns a Token with the given method and claims and a standard
// JOSE header ({"alg":..., "typ":"JWT"}).
func NewWithClaims(method SigningMethod, claims Claims) *Token {
	return &Token{
		Header: map[string]any{
			"alg": method.Alg(),
			"typ": "JWT",
		},
		Claims: claims,
		Method: method,
	}
}

// SigningString returns the signing input: base64url(header) + "." +
// base64url(payload). This is the value passed to SigningMethod.Sign/Verify.
func (t *Token) SigningString() (string, error) {
	header, err := json.Marshal(t.Header)
	if err != nil {
		return "", fmt.Errorf("%w: encoding header: %v", ErrInvalidToken, err)
	}
	claims, err := json.Marshal(t.Claims)
	if err != nil {
		return "", fmt.Errorf("%w: encoding claims: %v", ErrInvalidToken, err)
	}
	return EncodeSegment(header) + "." + EncodeSegment(claims), nil
}

// SignedString signs the token with key and returns the complete compact
// serialization (header.payload.signature).
func (t *Token) SignedString(key any) (string, error) {
	signingString, err := t.SigningString()
	if err != nil {
		return "", err
	}
	sig, err := t.Method.Sign(signingString, key)
	if err != nil {
		return "", err
	}
	return signingString + "." + EncodeSegment(sig), nil
}

// Sign is a convenience wrapper that builds a token from claims and method and
// returns its signed compact serialization.
func Sign(claims Claims, method SigningMethod, key any) (string, error) {
	return NewWithClaims(method, claims).SignedString(key)
}

// SetKID sets the "kid" (key ID) JOSE header, returning the token for chaining.
func (t *Token) SetKID(kid string) *Token {
	t.Header["kid"] = kid
	return t
}

// splitToken splits a compact serialization into its three parts, returning an
// error wrapping ErrTokenMalformed if the shape is wrong.
func splitToken(tokenString string) (parts []string, err error) {
	parts = strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: expected 3 parts, got %d", ErrTokenMalformed, len(parts))
	}
	return parts, nil
}
