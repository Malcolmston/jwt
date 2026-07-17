package jwt

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"time"
)

// Claims is implemented by any type that can be used as the payload of a JWT.
// Valid performs stateless self-validation and is invoked by the parser before
// the parser's own option-driven validation runs.
type Claims interface {
	// Valid reports whether the claims are internally consistent. It is called
	// during parsing; returning a non-nil error rejects the token. The
	// registered-claim time checks are performed separately by the parser's
	// validator, so lightweight implementations may simply return nil.
	Valid() error
}

// NumericDate wraps time.Time to marshal as a JSON numeric date: the number of
// seconds since the Unix epoch, per RFC 7519 §2. Fractional seconds are
// truncated on encode.
type NumericDate struct {
	time.Time
}

// NewNumericDate returns a *NumericDate for t, or nil if t is the zero time.
func NewNumericDate(t time.Time) *NumericDate {
	if t.IsZero() {
		return nil
	}
	return &NumericDate{t.Truncate(time.Second)}
}

// newNumericDateFromSeconds builds a *NumericDate from a (possibly fractional)
// count of seconds since the Unix epoch.
func newNumericDateFromSeconds(f float64) *NumericDate {
	sec, frac := math.Modf(f)
	return &NumericDate{time.Unix(int64(sec), int64(frac*1e9)).UTC()}
}

// MarshalJSON encodes the date as an integer number of seconds since the epoch.
func (d NumericDate) MarshalJSON() ([]byte, error) {
	if d.IsZero() {
		return []byte("null"), nil
	}
	return []byte(strconv.FormatInt(d.Unix(), 10)), nil
}

// UnmarshalJSON decodes a JSON number (possibly fractional) into the date.
func (d *NumericDate) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		return nil
	}
	f, err := strconv.ParseFloat(string(b), 64)
	if err != nil {
		return fmt.Errorf("%w: numeric date: %v", ErrInvalidType, err)
	}
	sec, frac := math.Modf(f)
	d.Time = time.Unix(int64(sec), int64(frac*1e9)).UTC()
	return nil
}

// ClaimStrings represents the JWT "aud" claim, which may be encoded either as a
// single string or as an array of strings (RFC 7519 §4.1.3). It always
// marshals back as an array unless it holds exactly one element handled by the
// caller.
type ClaimStrings []string

// UnmarshalJSON accepts either a JSON string or a JSON array of strings.
func (s *ClaimStrings) UnmarshalJSON(b []byte) error {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch val := v.(type) {
	case nil:
		*s = nil
	case string:
		*s = ClaimStrings{val}
	case []any:
		out := make(ClaimStrings, 0, len(val))
		for _, item := range val {
			str, ok := item.(string)
			if !ok {
				return fmt.Errorf("%w: aud array element is not a string", ErrInvalidType)
			}
			out = append(out, str)
		}
		*s = out
	default:
		return fmt.Errorf("%w: aud must be string or []string", ErrInvalidType)
	}
	return nil
}

// MarshalJSON encodes as a single string when there is exactly one audience,
// otherwise as an array. An empty value encodes as null (omitted with
// omitempty).
func (s ClaimStrings) MarshalJSON() ([]byte, error) {
	switch len(s) {
	case 0:
		return []byte("null"), nil
	case 1:
		return json.Marshal(s[0])
	default:
		return json.Marshal([]string(s))
	}
}

// RegisteredClaims holds the IANA-registered claim names from RFC 7519 §4.1.
// All fields are optional and omitted from the encoding when empty.
type RegisteredClaims struct {
	Issuer    string       `json:"iss,omitempty"`
	Subject   string       `json:"sub,omitempty"`
	Audience  ClaimStrings `json:"aud,omitempty"`
	ExpiresAt *NumericDate `json:"exp,omitempty"`
	NotBefore *NumericDate `json:"nbf,omitempty"`
	IssuedAt  *NumericDate `json:"iat,omitempty"`
	ID        string       `json:"jti,omitempty"`
}

// Valid satisfies the Claims interface. Time-based validation is performed by
// the parser's validator (with configurable leeway and clock), so this returns
// nil and defers to that machinery.
func (c RegisteredClaims) Valid() error { return nil }

// GetExpirationTime returns the exp claim.
func (c RegisteredClaims) GetExpirationTime() *NumericDate { return c.ExpiresAt }

// GetNotBefore returns the nbf claim.
func (c RegisteredClaims) GetNotBefore() *NumericDate { return c.NotBefore }

// GetIssuedAt returns the iat claim.
func (c RegisteredClaims) GetIssuedAt() *NumericDate { return c.IssuedAt }

// GetAudience returns the aud claim.
func (c RegisteredClaims) GetAudience() ClaimStrings { return c.Audience }

// GetIssuer returns the iss claim.
func (c RegisteredClaims) GetIssuer() string { return c.Issuer }

// GetSubject returns the sub claim.
func (c RegisteredClaims) GetSubject() string { return c.Subject }

// claimsGetter is the internal read interface the validator uses. Both
// RegisteredClaims and MapClaims implement it, letting the validator treat any
// claims uniformly.
type claimsGetter interface {
	GetExpirationTime() *NumericDate
	GetNotBefore() *NumericDate
	GetIssuedAt() *NumericDate
	GetAudience() ClaimStrings
	GetIssuer() string
	GetSubject() string
}
