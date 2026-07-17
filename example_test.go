package jwt_test

import (
	"crypto"
	"fmt"
	"time"

	"github.com/malcolmston/jwt"
)

// Example signs a token with HS256 and then parses and verifies it, printing a
// claim from the verified payload.
func Example() {
	secret := []byte("my-hmac-secret")

	// Use a fixed clock so the example is deterministic.
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	claims := jwt.RegisteredClaims{
		Issuer:    "auth.example.com",
		Subject:   "user-42",
		Audience:  jwt.ClaimStrings{"api.example.com"},
		ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		IssuedAt:  jwt.NewNumericDate(now),
	}

	signed, err := jwt.Sign(claims, jwt.SigningMethodHS256, secret)
	if err != nil {
		panic(err)
	}

	var parsed jwt.RegisteredClaims
	token, err := jwt.ParseWithClaims(signed, &parsed,
		func(t *jwt.Token) (any, error) { return secret, nil },
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithClock(jwt.ClockFunc(func() time.Time { return now })),
		jwt.WithAudience("api.example.com"),
		jwt.WithIssuer("auth.example.com"),
	)
	if err != nil {
		panic(err)
	}

	fmt.Println("valid:", token.Valid)
	fmt.Println("subject:", parsed.Subject)

	// Output:
	// valid: true
	// subject: user-42
}

// ExampleSignDetached demonstrates RFC 7797 detached, unencoded-payload JWS:
// the payload is signed as-is and carried out of band rather than embedded in
// the token.
func ExampleSignDetached() {
	secret := []byte("detached-secret")
	payload := []byte("arbitrary bytes, not base64url-encoded")

	jws, err := jwt.SignDetached(payload, jwt.SigningMethodHS256, secret, nil)
	if err != nil {
		panic(err)
	}

	tok, err := jwt.VerifyDetached(jws, payload,
		func(*jwt.Token) (any, error) { return secret, nil },
		jwt.WithValidMethods([]string{"HS256"}))
	if err != nil {
		panic(err)
	}
	fmt.Println("valid:", tok.Valid)

	// Output:
	// valid: true
}

// ExampleJSONWebKey_Thumbprint computes the RFC 7638 thumbprint of a JWK.
func ExampleJSONWebKey_Thumbprint() {
	jwk, err := jwt.ParseJWK([]byte(`{"kty":"oct","k":"AQAB"}`))
	if err != nil {
		panic(err)
	}
	tp, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		panic(err)
	}
	fmt.Println(jwt.EncodeSegment(tp))

	// Output:
	// 8uBm1Oeri9AB8y3VS0WbdSfBWsS34Z45nVhm9v0yh-k
}

// ExampleParseUnverified decodes a token without checking its signature, to
// read a header value (here the algorithm) before verification.
func ExampleParseUnverified() {
	signed, _ := jwt.Sign(jwt.MapClaims{"iss": "issuer"}, jwt.SigningMethodHS256, []byte("k"))

	tok, _, err := jwt.ParseUnverified(signed, jwt.MapClaims{})
	if err != nil {
		panic(err)
	}
	fmt.Println("alg:", tok.Header["alg"])
	fmt.Println("valid:", tok.Valid)

	// Output:
	// alg: HS256
	// valid: false
}
