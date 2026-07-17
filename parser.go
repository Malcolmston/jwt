package jwt

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"
)

// Keyfunc is called by the parser after the header is decoded, with the
// partially constructed token, to obtain the verification key. Implementations
// typically inspect token.Header (e.g. the "kid") and/or token.Method to
// choose the key. Returning an error aborts parsing.
type Keyfunc func(token *Token) (any, error)

// Parser parses and validates tokens according to its configured options. The
// zero value is usable but NewParser with options is the common path.
type Parser struct {
	validAlgs    []string
	allowNone    bool
	useJSONNumer bool
	validator    *validator
}

// ParserOption configures a Parser.
type ParserOption func(*Parser)

// NewParser constructs a Parser with the given options.
func NewParser(opts ...ParserOption) *Parser {
	p := &Parser{validator: newValidator()}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// WithValidMethods restricts the accepted alg header values to algs. This is
// the primary defense against algorithm-confusion attacks and should be set in
// production.
func WithValidMethods(algs []string) ParserOption {
	return func(p *Parser) { p.validAlgs = algs }
}

// WithLeeway sets a symmetric tolerance applied to exp, nbf, and iat checks.
func WithLeeway(d time.Duration) ParserOption {
	return func(p *Parser) { p.validator.leeway = d }
}

// WithClock injects the clock used for time-based validation, enabling
// deterministic tests.
func WithClock(c Clock) ParserOption {
	return func(p *Parser) { p.validator.clock = c }
}

// WithTimeFunc injects a time source as a function.
func WithTimeFunc(f func() time.Time) ParserOption {
	return func(p *Parser) { p.validator.clock = ClockFunc(f) }
}

// WithAudience requires that the aud claim contain aud.
func WithAudience(aud string) ParserOption {
	return func(p *Parser) { p.validator.expectedAud = aud }
}

// WithIssuer requires that the iss claim equal iss.
func WithIssuer(iss string) ParserOption {
	return func(p *Parser) { p.validator.expectedIss = iss }
}

// WithSubject requires that the sub claim equal sub.
func WithSubject(sub string) ParserOption {
	return func(p *Parser) { p.validator.expectedSub = sub }
}

// WithIssuedAt enables validation that iat is not in the future.
func WithIssuedAt() ParserOption {
	return func(p *Parser) { p.validator.verifyIAT = true }
}

// WithExpirationRequired rejects tokens that lack an exp claim.
func WithExpirationRequired() ParserOption {
	return func(p *Parser) { p.validator.expirationRequired = true }
}

// WithAllowNone permits the unsecured "none" algorithm. Without this option a
// token whose alg is "none" is rejected outright. Even with it enabled, the
// keyFunc must return UnsafeAllowNoneSignatureType as the key.
func WithAllowNone() ParserOption {
	return func(p *Parser) { p.allowNone = true }
}

// WithJSONNumber decodes claim numbers into json.Number rather than float64,
// preserving integer precision for large values. Applies to MapClaims.
func WithJSONNumber() ParserOption {
	return func(p *Parser) { p.useJSONNumer = true }
}

// Parse parses a compact JWT into a Token with MapClaims, using keyFunc to
// resolve the verification key, then verifies the signature and validates the
// claims. See ParseWithClaims to decode into a specific claims type.
func Parse(tokenString string, keyFunc Keyfunc, opts ...ParserOption) (*Token, error) {
	return NewParser(opts...).ParseWithClaims(tokenString, MapClaims{}, keyFunc)
}

// ParseWithClaims parses into the supplied claims value (which is populated in
// place), verifies the signature via keyFunc, and validates the claims.
func ParseWithClaims(tokenString string, claims Claims, keyFunc Keyfunc, opts ...ParserOption) (*Token, error) {
	return NewParser(opts...).ParseWithClaims(tokenString, claims, keyFunc)
}

// Parse is the method form; it decodes into MapClaims.
func (p *Parser) Parse(tokenString string, keyFunc Keyfunc) (*Token, error) {
	return p.ParseWithClaims(tokenString, MapClaims{}, keyFunc)
}

// ParseWithClaims decodes the token, resolves the key, verifies the signature,
// and validates the claims. On any failure it returns a nil-safe token (the
// partially parsed token may be returned alongside the error for inspection)
// and a wrapped error.
func (p *Parser) ParseWithClaims(tokenString string, claims Claims, keyFunc Keyfunc) (*Token, error) {
	token, parts, err := p.decode(tokenString, claims)
	if err != nil {
		return token, err
	}

	// Enforce the allowed-methods list, if configured.
	alg, _ := token.Header["alg"].(string)
	if len(p.validAlgs) > 0 && !contains(p.validAlgs, alg) {
		return token, fmt.Errorf("%w: alg %q is not accepted", ErrSignatureInvalid, alg)
	}
	if alg == "none" && !p.allowNone {
		return token, fmt.Errorf("%w", ErrNoneAlgDisallowed)
	}

	if keyFunc == nil {
		return token, fmt.Errorf("%w: no keyfunc provided", ErrTokenUnverifiable)
	}
	key, err := keyFunc(token)
	if err != nil {
		return token, fmt.Errorf("%w: %v", ErrTokenUnverifiable, err)
	}

	signingString := parts[0] + "." + parts[1]
	if err := token.Method.Verify(signingString, token.Signature, key); err != nil {
		return token, err
	}

	// Claims self-validation followed by option-driven validation.
	if err := token.Claims.Valid(); err != nil {
		return token, err
	}
	if getter, ok := token.Claims.(claimsGetter); ok {
		if err := p.validator.Validate(getter); err != nil {
			return token, err
		}
	}

	token.Valid = true
	return token, nil
}

// decode splits the token, decodes the header and claims, and selects the
// signing method, without touching the key or signature verification.
func (p *Parser) decode(tokenString string, claims Claims) (*Token, []string, error) {
	parts, err := splitToken(tokenString)
	if err != nil {
		return nil, nil, err
	}

	token := &Token{Raw: tokenString, Claims: claims}

	headerBytes, err := DecodeSegment(parts[0])
	if err != nil {
		return token, parts, fmt.Errorf("%w: decoding header: %v", ErrTokenMalformed, err)
	}
	if err := json.Unmarshal(headerBytes, &token.Header); err != nil {
		return token, parts, fmt.Errorf("%w: parsing header: %v", ErrTokenMalformed, err)
	}

	claimBytes, err := DecodeSegment(parts[1])
	if err != nil {
		return token, parts, fmt.Errorf("%w: decoding claims: %v", ErrTokenMalformed, err)
	}
	dec := json.NewDecoder(bytes.NewReader(claimBytes))
	if p.useJSONNumer {
		dec.UseNumber()
	}
	// json requires a pointer destination. Struct claims are already passed by
	// pointer; MapClaims is a reference type passed by value, so decode through
	// a local pointer and re-store the (possibly reallocated) map.
	if mc, ok := claims.(MapClaims); ok {
		if err := dec.Decode(&mc); err != nil {
			return token, parts, fmt.Errorf("%w: parsing claims: %v", ErrTokenMalformed, err)
		}
		token.Claims = mc
	} else {
		if err := dec.Decode(claims); err != nil {
			return token, parts, fmt.Errorf("%w: parsing claims: %v", ErrTokenMalformed, err)
		}
	}

	token.Signature, err = DecodeSegment(parts[2])
	if err != nil {
		return token, parts, fmt.Errorf("%w: decoding signature: %v", ErrTokenMalformed, err)
	}

	alg, ok := token.Header["alg"].(string)
	if !ok {
		return token, parts, fmt.Errorf("%w: missing alg header", ErrTokenMalformed)
	}
	method := GetSigningMethod(alg)
	if method == nil {
		return token, parts, fmt.Errorf("%w: %q", ErrSigningMethodUnavailable, alg)
	}
	token.Method = method

	return token, parts, nil
}

func contains(list []string, s string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}
