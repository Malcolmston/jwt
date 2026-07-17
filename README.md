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
  - Unsecured `none` (opt-in twice: parser option plus a sentinel key)
- `RegisteredClaims` (iss, sub, aud, exp, nbf, iat, jti) with numeric-date
  encoding and string-or-array audience, `MapClaims` for arbitrary claims, and
  support for any custom struct that implements the `Claims` interface.
- Base64url (no padding) encoding of header, payload, and signature.
- `Parse` / `ParseWithClaims` with a `Keyfunc` for key selection (e.g. by
  `kid`), signature verification, and validation of exp/nbf/iat, audience,
  issuer, and subject.
- Injectable clock and configurable leeway for deterministic time validation.
- PEM key helpers for RSA and EC public/private keys.
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
`WithAllowNone`, `WithJSONNumber`.

## License

See repository.
