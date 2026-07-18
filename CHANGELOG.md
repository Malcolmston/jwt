# Changelog

All notable changes to this project are documented in this file. The format is
loosely based on [Keep a Changelog](https://keepachangelog.com/), and the
project aims to follow semantic versioning.

## [0.3.0] - 2026-07-18

### Added

- **PEM key encoders** (the inverse of the existing parsers):
  `EncodeRSAPrivateKeyToPEM`, `EncodeRSAPublicKeyToPEM`,
  `EncodeECPrivateKeyToPEM`, `EncodeECPublicKeyToPEM`, `EncodeEdPrivateKeyToPEM`,
  `EncodeEdPublicKeyToPEM`, plus the algorithm-agnostic `EncodePublicKeyToPEM`
  (PKIX) and `EncodePrivateKeyToPEM` (PKCS#8).
- **JWK construction & serialization** (RFC 7517, the reverse of `ParseJWK`):
  `NewJSONWebKey` builds a `JSONWebKey` from an RSA, EC, Ed25519, or oct Go key;
  chainable `JSONWebKey.WithKeyID` / `WithAlgorithm` / `WithUse` and
  `JSONWebKeySet.Add` assemble a publishable key set.
- **Thumbprint helpers**: `JSONWebKey.Base64Thumbprint`, `JSONWebKey.ThumbprintURI`
  (RFC 9278 `urn:ietf:params:oauth:jwk-thumbprint:...`), and `ComputeKeyID`
  (a deterministic `kid` from any key's RFC 7638 SHA-256 thumbprint).
- **`MapClaims` verification & typed accessors** (golang-jwt v4 parity):
  `VerifyAudience`, `VerifyExpiresAt`, `VerifyIssuedAt`, `VerifyNotBefore`,
  `VerifyIssuer`, plus `GetInt64`, `GetFloat64`, `GetBool`, `GetStringSlice`,
  `GetTime`, `Set`, and `Has`.
- **Public `Validator`** (golang-jwt v5 parity): `NewValidator` and
  `Validator.Validate` run the parser's claim checks against claims obtained
  independently of parsing.
- **Token header helpers**: `Token.SetHeader`, `SetType`, `KeyID`, `TokenType`,
  and `HeaderString`.
- **New parser options**: `WithStrictDecoding` (reject base64url padding),
  `WithPaddingAllowed` (its inverse), and `WithoutClaimsValidation` (verify the
  signature but skip claim validation).
- **Registry & claim helpers**: `UnregisterSigningMethod` (inverse of
  `RegisterSigningMethod`) and `RegisteredClaims.GetID`.

## [0.2.0] - 2026-07-17

### Added

- **EdDSA (Ed25519)** signing method (`SigningMethodEdDSA`, alg `"EdDSA"`) via
  `crypto/ed25519`, plus `ParseEdPrivateKeyFromPEM` / `ParseEdPublicKeyFromPEM`.
- **JWK / JWKS support** (RFC 7517):
  - `ParseJWK` and `ParseJWKSet` decode RSA, EC (P-256/384/521), OKP (Ed25519),
    and oct keys into Go crypto keys.
  - `JSONWebKey.Thumbprint` implements RFC 7638 JWK thumbprints.
  - `JSONWebKey.Public` / `IsPrivate`, and `JSONWebKeySet.LookupKeyID` / `Key` /
    `Keyfunc` (kid lookup with alg-match enforcement).
  - `JWKSCache`: a remote JWKS fetcher/cache keyed by URL over `net/http` with
    TTL refresh, kid-miss refresh (rate-limited), and an injectable `HTTPDoer`
    for tests. Exposes `KeySet`, `Refresh`, `Keyfunc`, and `KeyfuncCtx`.
- **Detached / unencoded payload** (RFC 7797, `b64=false`): `SignDetached` and
  `VerifyDetached`.
- **`ParseUnverified`** (decode without signature/claims verification) and
  `Token.String()` for a lossless parse/serialize round-trip (`SignedString`
  now also populates `Token.Raw`).
- New parser options: `WithMaxTokenAge`, `WithRequiredClaims`, `WithValidTypes`,
  and `WithKnownCriticalHeaders`. The parser now enforces JOSE `crit` handling
  (unknown critical headers are rejected per RFC 7515) and optional `typ`
  validation.
- `MapClaims` convenience accessors: `GetID`, `GetNonce`, `GetAuthorizedParty`,
  and `GetString`.

### Security

- Every signing method type-asserts its key, so a token cannot be verified with
  a key of the wrong type (algorithm-confusion defense), including the new
  EdDSA method. The `none` algorithm remains opt-in twice over.

## [0.1.0]

### Added

- Initial release: HMAC, RSA PKCS1v15, RSA-PSS, and ECDSA signing methods; the
  unsecured `none` method; `RegisteredClaims`, `MapClaims`, and custom struct
  claims; `Parse` / `ParseWithClaims` with a `Keyfunc`, validation options, an
  injectable clock, and PEM key helpers for RSA and EC keys.
