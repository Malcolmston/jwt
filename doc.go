// Package jwt is a standard-library-only implementation of JSON Web Tokens
// (RFC 7519) and the underlying JSON Web Signature compact serialization
// (RFC 7515).
//
// # Overview
//
// A JWT is three base64url-encoded, dot-separated parts: a JOSE header, a set
// of claims (the payload), and a signature computed over "header.payload". This
// package signs and verifies tokens, encodes and validates the registered
// claims, and parses PEM key material — all using only the Go standard library
// (crypto/*, encoding/*, math/big, ...). There are no third-party dependencies
// and no cgo.
//
// # Signing methods
//
// Every algorithm implements the SigningMethod interface. The following are
// registered on import:
//
//	HMAC-SHA:    HS256, HS384, HS512   (key: []byte)
//	RSA PKCS1v15: RS256, RS384, RS512  (sign: *rsa.PrivateKey, verify: *rsa.PublicKey)
//	RSA-PSS:     PS256, PS384, PS512   (sign: *rsa.PrivateKey, verify: *rsa.PublicKey)
//	ECDSA:       ES256, ES384, ES512   (sign: *ecdsa.PrivateKey, verify: *ecdsa.PublicKey)
//	Unsecured:   none                  (key: jwt.UnsafeAllowNoneSignatureType)
//
// ECDSA signatures use the fixed-width r||s encoding required by RFC 7518, not
// ASN.1 DER. The "none" method is opt-in twice over: the parser must be given
// WithAllowNone and the key must be the sentinel UnsafeAllowNoneSignatureType.
//
// # Claims
//
// RegisteredClaims models the IANA-registered claims (iss, sub, aud, exp, nbf,
// iat, jti). Times use NumericDate (seconds since the Unix epoch) and the
// audience uses ClaimStrings, which decodes from either a JSON string or an
// array of strings. MapClaims (a map[string]any) handles arbitrary claim sets.
// Any custom struct may be used as claims so long as it implements the Claims
// interface (a single Valid method); embedding RegisteredClaims is the simplest
// way to do so.
//
// # Signing
//
// Build and sign a token in one of two equivalent ways:
//
//	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
//	s, err := tok.SignedString([]byte("secret"))
//
//	s, err := jwt.Sign(claims, jwt.SigningMethodHS256, []byte("secret"))
//
// # Parsing and validation
//
// Parse resolves the verification key through a Keyfunc, which receives the
// decoded token (including its header, e.g. "kid") so it can select the correct
// key. Parse decodes into MapClaims; ParseWithClaims decodes into a caller-
// supplied claims value:
//
//	tok, err := jwt.Parse(s, func(t *jwt.Token) (any, error) {
//	        return []byte("secret"), nil
//	}, jwt.WithValidMethods([]string{"HS256"}))
//
// Parser options configure validation: WithValidMethods (reject unexpected
// algorithms), WithLeeway, WithClock / WithTimeFunc (deterministic time),
// WithAudience, WithIssuer, WithSubject, WithIssuedAt, WithExpirationRequired,
// and WithAllowNone. The exp, nbf, and (optionally) iat claims are checked
// against the injected clock with the configured leeway.
//
// All errors are wrapped sentinels; test them with errors.Is, e.g.
// errors.Is(err, jwt.ErrTokenExpired) or errors.Is(err, jwt.ErrSignatureInvalid).
//
// # Keys
//
// ParseRSAPrivateKeyFromPEM, ParseRSAPublicKeyFromPEM, ParseECPrivateKeyFromPEM,
// and ParseECPublicKeyFromPEM read PEM-encoded key material (PKCS#1, SEC1,
// PKCS#8, PKIX, and certificates as applicable).
package jwt
