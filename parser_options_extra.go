package jwt

// WithStrictDecoding configures the parser to reject any base64url segment that
// carries '=' padding characters. The JWS compact serialization mandates
// unpadded base64url (RFC 7515 §2, RFC 7797), so strict decoding matches the
// specification exactly. It is the opposite of WithPaddingAllowed; the last of
// the two options applied wins.
func WithStrictDecoding() ParserOption {
	return func(p *Parser) { p.strictDecode = true }
}

// WithPaddingAllowed configures the parser to accept base64url segments that
// carry '=' padding, tolerating producers that violate the unpadded-base64url
// requirement of the compact serialization. This is the parser's default
// behavior; the option exists for API symmetry and to re-enable tolerance on a
// parser that a caller (or a reused base Parser) previously put into strict
// mode with WithStrictDecoding.
func WithPaddingAllowed() ParserOption {
	return func(p *Parser) { p.strictDecode = false }
}

// WithIgnoreExpiration disables the exp (expiration) claim check while leaving
// every other validation — signature, nbf, iat, audience, issuer, subject and
// required-claim checks — in force. It mirrors the "ignoreExpiration" option of
// node's jsonwebtoken and is narrower than WithoutClaimsValidation, which
// suppresses all claim checks. Because WithExpirationRequired is itself part of
// the exp check, it too is suppressed when expiration is ignored.
func WithIgnoreExpiration() ParserOption {
	return func(p *Parser) { p.validator.ignoreExp = true }
}

// WithIgnoreNotBefore disables the nbf (not-before) claim check while leaving
// every other validation in force. It mirrors the "ignoreNotBefore" option of
// node's jsonwebtoken, letting a caller accept a token whose validity window
// has not yet opened without also relaxing the exp, audience, issuer or subject
// checks.
func WithIgnoreNotBefore() ParserOption {
	return func(p *Parser) { p.validator.ignoreNbf = true }
}

// WithoutClaimsValidation disables all claim validation performed after the
// signature is verified: the Claims.Valid self-check, the registered time and
// equality checks (exp, nbf, iat, aud, iss, sub, max-token-age), and the
// WithRequiredClaims presence checks are all skipped. The signature is still
// verified, so the token's authenticity is unaffected; only the semantic
// validity of its claims is left to the caller. Use this when the application
// enforces its own claim policy, or to inspect the claims of an authentic but
// possibly expired token.
func WithoutClaimsValidation() ParserOption {
	return func(p *Parser) { p.skipClaimsValidation = true }
}
