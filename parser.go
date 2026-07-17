package jwt

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
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
	validAlgs      []string
	allowNone      bool
	useJSONNumer   bool
	validTypes     []string
	requiredClaims []string
	knownCrit      map[string]bool
	validator      *validator
}

// ParserOption configures a Parser.
type ParserOption func(*Parser)

// NewParser constructs a Parser with the given options.
func NewParser(opts ...ParserOption) *Parser {
	// "b64" (RFC 7797 unencoded payload) is the only critical header this
	// parser understands; any other value in "crit" is rejected.
	p := &Parser{validator: newValidator(), knownCrit: map[string]bool{"b64": true}}
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

// WithMaxTokenAge rejects a token whose age — the difference between the
// verification time and its iat claim — exceeds d. The iat claim becomes
// required; a token without it is rejected. This mirrors the "maxAge" option of
// node's jsonwebtoken.
func WithMaxTokenAge(d time.Duration) ParserOption {
	return func(p *Parser) { p.validator.maxTokenAge = d }
}

// WithRequiredClaims rejects a token that does not carry every named claim (with
// a non-null value). Use it to insist on, e.g., "jti" or a custom claim
// regardless of the claims type in use.
func WithRequiredClaims(names ...string) ParserOption {
	return func(p *Parser) { p.requiredClaims = append(p.requiredClaims, names...) }
}

// WithValidTypes restricts the accepted JOSE "typ" header values to types. A
// token whose typ header is present but not listed is rejected; a token with no
// typ header is accepted (the header is optional per RFC 7519). Comparison is
// case-insensitive, matching how "JWT" is conventionally written.
func WithValidTypes(types ...string) ParserOption {
	return func(p *Parser) { p.validTypes = append(p.validTypes, types...) }
}

// WithKnownCriticalHeaders registers additional JOSE "crit" header extension
// names the caller understands and will process out of band. By default only
// "b64" (RFC 7797) is recognized; any unrecognized critical header causes the
// token to be rejected, as required by RFC 7515 §4.1.11.
func WithKnownCriticalHeaders(names ...string) ParserOption {
	return func(p *Parser) {
		for _, n := range names {
			p.knownCrit[n] = true
		}
	}
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

	// Validate JOSE header constraints (typ and crit) before doing any crypto.
	if err := p.checkHeader(token); err != nil {
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
	if err := p.checkRequiredClaims(token.Claims); err != nil {
		return token, err
	}

	token.Valid = true
	return token, nil
}

// checkHeader enforces the typ and crit JOSE header constraints.
func (p *Parser) checkHeader(token *Token) error {
	if len(p.validTypes) > 0 {
		if typ, ok := token.Header["typ"].(string); ok && typ != "" {
			if !containsFold(p.validTypes, typ) {
				return fmt.Errorf("%w: %q", ErrInvalidTyp, typ)
			}
		}
	}
	crit, ok := token.Header["crit"]
	if !ok {
		return nil
	}
	list, ok := crit.([]any)
	if !ok {
		return fmt.Errorf("%w: crit must be an array of strings", ErrInvalidCrit)
	}
	for _, item := range list {
		name, ok := item.(string)
		if !ok {
			return fmt.Errorf("%w: crit entries must be strings", ErrInvalidCrit)
		}
		// A critical header must also be present in the JOSE header (RFC 7515
		// §4.1.11) and must be one the parser knows how to process.
		if _, present := token.Header[name]; !present {
			return fmt.Errorf("%w: critical header %q is absent", ErrInvalidCrit, name)
		}
		if !p.knownCrit[name] {
			return fmt.Errorf("%w: unrecognized critical header %q", ErrInvalidCrit, name)
		}
	}
	return nil
}

// checkRequiredClaims verifies that every claim named by WithRequiredClaims is
// present and non-null. It works for any Claims type by round-tripping through
// JSON.
func (p *Parser) checkRequiredClaims(claims Claims) error {
	if len(p.requiredClaims) == 0 {
		return nil
	}
	data, err := json.Marshal(claims)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("%w: claims are not a JSON object", ErrInvalidToken)
	}
	for _, name := range p.requiredClaims {
		v, ok := raw[name]
		if !ok || string(v) == "null" {
			return fmt.Errorf("%w: %s", ErrTokenRequiredClaimMissing, name)
		}
	}
	return nil
}

// ParseUnverified decodes a token's header and claims WITHOUT verifying the
// signature or validating the claims. It is useful for inspecting a token
// (e.g. reading the "kid" or "iss" to choose a key or key set) before
// verification. The returned token has Valid == false and its Signature
// decoded but unchecked.
//
// SECURITY: never trust the claims of a token returned by ParseUnverified. Use
// Parse or ParseWithClaims for any token whose contents drive a decision.
func (p *Parser) ParseUnverified(tokenString string, claims Claims) (*Token, []string, error) {
	return p.decode(tokenString, claims)
}

// ParseUnverified is the package-level convenience form of
// Parser.ParseUnverified, decoding into the supplied claims value without
// verifying the signature. See the method for the security caveat.
func ParseUnverified(tokenString string, claims Claims) (*Token, []string, error) {
	return NewParser().ParseUnverified(tokenString, claims)
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

// containsFold reports whether list contains s under ASCII case-insensitive
// comparison.
func containsFold(list []string, s string) bool {
	for _, item := range list {
		if strings.EqualFold(item, s) {
			return true
		}
	}
	return false
}
