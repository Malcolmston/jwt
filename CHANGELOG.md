# Changelog

All notable changes to this project are documented in this file. The format is
loosely based on [Keep a Changelog](https://keepachangelog.com/), and the
project aims to follow semantic versioning.

## [0.4.0] - 2026-08-11

### Security

- **Algorithm confusion via a public key used as an HMAC secret**
  ([GHSA-75rm-5v4f-887v]). The HMAC methods (`HS256`/`HS384`/`HS512`) accepted
  any `[]byte` as a secret, so a token MACed with the bytes of the verifier's
  RSA or EC **public** key — material an attacker has by definition — verified
  successfully whenever no `WithValidMethods` allowlist was configured. `HS*`
  `Sign` and `Verify` now refuse asymmetric key material and return the new
  `ErrAsymmetricKeyForHMAC`: PEM blocks, bare DER keys, certificates, and typed
  `*rsa.PublicKey` / `*rsa.PrivateKey` / `*ecdsa.PublicKey` / `*ecdsa.PrivateKey`
  / `ed25519.PublicKey` / `ed25519.PrivateKey` values are all rejected. The
  guard is applied on the signing path as well, so this package will not mint
  the forgery its verifier rejects (matching node jsonwebtoken, which both
  infers the algorithm family from the key material and insists on a symmetric
  key for `HS*`).
- **An empty algorithm allowlist restricted nothing** ([GHSA-2vc9-3gjf-2276]).
  `WithValidMethods([]string{})` was treated as "no allowlist configured"
  because the check was `len(algs) > 0`, so a computed-empty list — a filtered
  configuration value that came out empty, say — silently disabled the primary
  algorithm-confusion defense. The parser now distinguishes a `nil` slice (no
  allowlist) from an empty non-nil slice (an allowlist that permits nothing, so
  every token is rejected with `ErrSignatureInvalid`). This applies to
  `Parse`, `ParseWithClaims`, and `VerifyDetached`.

### Added

- `ErrAsymmetricKeyForHMAC`, so callers can distinguish "you handed an `HS*`
  method a key belonging to an asymmetric algorithm" from other key-type
  errors. It wraps `ErrInvalidKeyType`, so existing `errors.Is` checks against
  the broader category continue to match.

### Changed (breaking for affected callers — deliberately)

Both fixes turn a silently-accepted operation into an error. This is the point
of the release, but it can break working code:

- A caller that passed a PEM/DER public or private key (or a typed asymmetric
  key value) as an `HS*` secret now gets `ErrAsymmetricKeyForHMAC` from `Sign`,
  `SignedString`, `SignDetached`, `Parse`, and `VerifyDetached`. Such a
  deployment was exploitable; the fix is to use a real symmetric secret, or the
  matching asymmetric signing method (`RS*`/`PS*`/`ES*`/`EdDSA`).
- A caller that passed an empty non-nil `WithValidMethods` list — most often a
  list computed from configuration — now rejects every token instead of
  accepting every algorithm. Pass `nil` (or omit the option) for the previous
  "no allowlist" behavior, though naming the algorithms you accept is strongly
  preferred.
- Legitimate symmetric secrets, including random secrets of key-like length,
  are unaffected.

[GHSA-75rm-5v4f-887v]: https://github.com/malcolmston/jwt/security/advisories/GHSA-75rm-5v4f-887v
[GHSA-2vc9-3gjf-2276]: https://github.com/malcolmston/jwt/security/advisories/GHSA-2vc9-3gjf-2276

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
