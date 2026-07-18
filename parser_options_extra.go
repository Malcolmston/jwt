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
