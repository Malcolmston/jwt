package jwt

import (
	"encoding/json"
	"fmt"
)

// Validator validates a set of claims independently of parsing and signature
// verification. It is configured with the same time- and equality-based
// ParserOptions used by Parse (WithLeeway, WithClock, WithTimeFunc,
// WithAudience, WithIssuer, WithSubject, WithIssuedAt, WithExpirationRequired,
// WithMaxTokenAge, WithRequiredClaims), letting a caller re-run the parser's
// claim checks against claims obtained elsewhere — for example after
// ParseUnverified, or against claims assembled by the application. A Validator
// is safe for concurrent use as long as its injected Clock is.
type Validator struct {
	v              *validator
	requiredClaims []string
}

// NewValidator builds a Validator from the given options. Only the validation
// options listed on the Validator type have any effect; options that concern
// signing methods, decoding, or header handling are accepted but ignored.
func NewValidator(opts ...ParserOption) *Validator {
	p := NewParser(opts...)
	return &Validator{v: p.validator, requiredClaims: p.requiredClaims}
}

// Validate runs the configured checks against claims and returns nil if they
// all pass. It first invokes claims.Valid (the type's own self-check), then, if
// the claims expose the registered getters (as RegisteredClaims and MapClaims
// do), the time and equality checks, and finally the required-claim presence
// checks. Multiple failures are joined so the result can be tested for any of
// them with errors.Is.
func (val *Validator) Validate(claims Claims) error {
	if err := claims.Valid(); err != nil {
		return err
	}
	if getter, ok := claims.(claimsGetter); ok {
		if err := val.v.Validate(getter); err != nil {
			return err
		}
	}
	return val.checkRequired(claims)
}

// checkRequired verifies that every claim named by WithRequiredClaims is present
// and non-null, round-tripping the claims through JSON so it works for any
// Claims type.
func (val *Validator) checkRequired(claims Claims) error {
	if len(val.requiredClaims) == 0 {
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
	for _, name := range val.requiredClaims {
		v, ok := raw[name]
		if !ok || string(v) == "null" {
			return fmt.Errorf("%w: %s", ErrTokenRequiredClaimMissing, name)
		}
	}
	return nil
}
