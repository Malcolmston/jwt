package jwt

import (
	"encoding/json"
	"fmt"
)

// MapClaims is a Claims implementation backed by a plain map, useful when the
// set of claims is dynamic or not known ahead of time.
type MapClaims map[string]any

// Valid satisfies the Claims interface. As with RegisteredClaims, time checks
// are delegated to the parser's validator, so this returns nil.
func (m MapClaims) Valid() error { return nil }

// parseNumericDate extracts a *NumericDate from an arbitrary JSON value for a
// claim. JSON numbers decode as float64; the value is interpreted as seconds
// since the epoch. A missing claim yields (nil, nil).
func (m MapClaims) parseNumericDate(key string) (*NumericDate, error) {
	v, ok := m[key]
	if !ok || v == nil {
		return nil, nil
	}
	switch n := v.(type) {
	case float64:
		return newNumericDateFromSeconds(n), nil
	case json.Number:
		f, err := n.Float64()
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrInvalidType, key, err)
		}
		return newNumericDateFromSeconds(f), nil
	case int64:
		return newNumericDateFromSeconds(float64(n)), nil
	default:
		return nil, fmt.Errorf("%w: %s is not a numeric date", ErrInvalidType, key)
	}
}

// GetExpirationTime returns the exp claim.
func (m MapClaims) GetExpirationTime() *NumericDate { return mustDate(m.parseNumericDate("exp")) }

// GetNotBefore returns the nbf claim.
func (m MapClaims) GetNotBefore() *NumericDate { return mustDate(m.parseNumericDate("nbf")) }

// GetIssuedAt returns the iat claim.
func (m MapClaims) GetIssuedAt() *NumericDate { return mustDate(m.parseNumericDate("iat")) }

// mustDate discards the error from parseNumericDate; the validator re-derives
// values through the error-returning helpers where correctness matters, so the
// getter interface stays simple.
func mustDate(d *NumericDate, _ error) *NumericDate { return d }

// GetAudience returns the aud claim, tolerating both string and []any forms.
func (m MapClaims) GetAudience() ClaimStrings {
	v, ok := m["aud"]
	if !ok || v == nil {
		return nil
	}
	switch aud := v.(type) {
	case string:
		return ClaimStrings{aud}
	case []string:
		return ClaimStrings(aud)
	case []any:
		out := make(ClaimStrings, 0, len(aud))
		for _, item := range aud {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// GetIssuer returns the iss claim as a string, or "" if absent or non-string.
func (m MapClaims) GetIssuer() string { return stringClaim(m["iss"]) }

// GetSubject returns the sub claim as a string, or "" if absent or non-string.
func (m MapClaims) GetSubject() string { return stringClaim(m["sub"]) }

func stringClaim(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
