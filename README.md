# jwt

A JSON Web Token library for Go, implementing RFC 7519 (JWT) on top of RFC 7515
(JWS compact serialization). It is built entirely on the Go standard library:
no third-party modules, no cgo, no `require` directives.

## Features

- **Signing methods** via a `SigningMethod` interface:
  - HMAC-SHA: `HS256`, `HS384`, `HS512`
  - RSA PKCS1v15: `RS256`, `RS384`, `RS512`
  - RSA-PSS: `PS256`, `PS384`, `PS512`
  - ECDSA (fixed-width `r||s` encoding): `ES256`, `ES384`, `ES512`
  - EdDSA (Ed25519): `EdDSA`
  - Unsecured `none` (opt-in twice: parser option plus a sentinel key)
  - Every method type-asserts its key, closing the algorithm-confusion attack.
- **JWK / JWKS** (RFC 7517): `ParseJWK` / `ParseJWKSet` decode RSA, EC, OKP
  (Ed25519), and oct keys; `JSONWebKey.Thumbprint` implements RFC 7638;
  `JSONWebKeySet.LookupKeyID` / `.Keyfunc` select a key by `kid`; and
  `JWKSCache` fetches and caches a remote JWKS over `net/http` (injectable
  `HTTPDoer`) with TTL and kid-miss refresh.
- **Detached / unencoded payload** (RFC 7797, `b64=false`) via `SignDetached` /
  `VerifyDetached`.
- `RegisteredClaims` (iss, sub, aud, exp, nbf, iat, jti) with numeric-date
  encoding and string-or-array audience, `MapClaims` (with `GetNonce`,
  `GetAuthorizedParty`, `GetID`, `GetString` helpers) for arbitrary claims, and
  support for any custom struct that implements the `Claims` interface.
- Base64url (no padding) encoding of header, payload, and signature.
- `Parse` / `ParseWithClaims` with a `Keyfunc` for key selection (e.g. by
  `kid`), signature verification, and validation of exp/nbf/iat, audience,
  issuer, subject, max-token-age, and required claims. `ParseUnverified`
  decodes without verifying, and `Token.String()` re-serializes.
- Reusable `Parser` (`NewParser(opts...)`) and JOSE `crit` / `typ` header
  handling (unknown critical headers are rejected).
- Injectable clock and configurable leeway for deterministic time validation.
- PEM key helpers for RSA, EC, and Ed25519 public/private keys.
- Wrapped sentinel errors for use with `errors.Is`.

## Install

```sh
go get github.com/malcolmston/jwt
```

Requires Go 1.24 or newer.

## Quick start

### Sign

```go
claims := jwt.RegisteredClaims{
    Issuer:    "auth.example.com",
    Subject:   "user-42",
    Audience:  jwt.ClaimStrings{"api.example.com"},
    ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
    IssuedAt:  jwt.NewNumericDate(time.Now()),
}

signed, err := jwt.Sign(claims, jwt.SigningMethodHS256, []byte("my-hmac-secret"))
```

### Parse and verify

```go
var claims jwt.RegisteredClaims
token, err := jwt.ParseWithClaims(signed, &claims,
    func(t *jwt.Token) (any, error) {
        // Select the key, e.g. by t.Header["kid"].
        return []byte("my-hmac-secret"), nil
    },
    jwt.WithValidMethods([]string{"HS256"}), // reject algorithm confusion
    jwt.WithAudience("api.example.com"),
    jwt.WithIssuer("auth.example.com"),
    jwt.WithLeeway(30*time.Second),
)
if err != nil {
    // errors.Is(err, jwt.ErrTokenExpired), jwt.ErrSignatureInvalid, ...
}
fmt.Println(token.Valid, claims.Subject)
```

### Asymmetric keys

```go
priv, _ := jwt.ParseRSAPrivateKeyFromPEM(privPEM)
signed, _ := jwt.Sign(claims, jwt.SigningMethodRS256, priv)

pub, _ := jwt.ParseRSAPublicKeyFromPEM(pubPEM)
token, _ := jwt.Parse(signed, func(*jwt.Token) (any, error) { return pub, nil },
    jwt.WithValidMethods([]string{"RS256"}))
```

### Deterministic validation in tests

```go
clock := jwt.ClockFunc(func() time.Time { return fixedTime })
jwt.Parse(signed, keyFunc, jwt.WithClock(clock))
```

## Parser options

`WithValidMethods`, `WithLeeway`, `WithClock`, `WithTimeFunc`, `WithAudience`,
`WithIssuer`, `WithSubject`, `WithIssuedAt`, `WithExpirationRequired`,
`WithMaxTokenAge`, `WithRequiredClaims`, `WithValidTypes`,
`WithKnownCriticalHeaders`, `WithAllowNone`, `WithJSONNumber`.

## JWKS

```go
// Verify against a provider's rotating JWKS, cached and refreshed on demand.
cache := jwt.NewJWKSCache("https://issuer.example/.well-known/jwks.json")
token, err := jwt.Parse(signed, cache.Keyfunc(),
    jwt.WithValidMethods([]string{"RS256", "ES256", "EdDSA"}),
    jwt.WithIssuer("https://issuer.example"))
```

## Detached payload (RFC 7797)

```go
jws, _ := jwt.SignDetached(payload, jwt.SigningMethodEdDSA, edPriv, nil)
// jws is "header..signature"; the payload travels out of band.
tok, err := jwt.VerifyDetached(jws, payload,
    func(*jwt.Token) (any, error) { return edPub, nil },
    jwt.WithValidMethods([]string{"EdDSA"}))
```

## License

See repository.
