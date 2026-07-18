package jwt

import (
	"encoding/json"
	"time"
)

// VerifyAudience reports whether the "aud" claim contains cmp. When req is false
// and the claim is absent, verification passes; when req is true, an absent
// claim fails. This mirrors the golang-jwt v4 MapClaims API.
func (m MapClaims) VerifyAudience(cmp string, req bool) bool {
	aud := m.GetAudience()
	if len(aud) == 0 {
		return !req
	}
	for _, a := range aud {
		if a == cmp {
			return true
		}
	}
	return false
}

// VerifyExpiresAt reports whether the token is unexpired relative to cmp (a Unix
// timestamp in seconds): it passes when exp is strictly after cmp. When req is
// false and the claim is absent, verification passes; when req is true, an
// absent claim fails.
func (m MapClaims) VerifyExpiresAt(cmp int64, req bool) bool {
	exp := m.GetExpirationTime()
	if exp == nil {
		return !req
	}
	return cmp < exp.Unix()
}

// VerifyIssuedAt reports whether the "iat" claim is at or before cmp (a Unix
// timestamp in seconds), i.e. the token was not issued in the future relative to
// cmp. When req is false and the claim is absent, verification passes; when req
// is true, an absent claim fails.
func (m MapClaims) VerifyIssuedAt(cmp int64, req bool) bool {
	iat := m.GetIssuedAt()
	if iat == nil {
		return !req
	}
	return cmp >= iat.Unix()
}

// VerifyNotBefore reports whether the "nbf" claim is at or before cmp (a Unix
// timestamp in seconds), i.e. the token is already valid relative to cmp. When
// req is false and the claim is absent, verification passes; when req is true,
// an absent claim fails.
func (m MapClaims) VerifyNotBefore(cmp int64, req bool) bool {
	nbf := m.GetNotBefore()
	if nbf == nil {
		return !req
	}
	return cmp >= nbf.Unix()
}

// VerifyIssuer reports whether the "iss" claim equals cmp. When req is false and
// the claim is absent, verification passes; when req is true, an absent claim
// fails.
func (m MapClaims) VerifyIssuer(cmp string, req bool) bool {
	iss := m.GetIssuer()
	if iss == "" {
		return !req
	}
	return iss == cmp
}

// GetInt64 returns the claim key as an int64 together with true when it is
// present and holds an integral numeric value (float64, json.Number, or an
// integer type). It returns (0, false) otherwise.
func (m MapClaims) GetInt64(key string) (int64, bool) {
	switch n := m[key].(type) {
	case float64:
		return int64(n), true
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return i, true
		}
		if f, err := n.Float64(); err == nil {
			return int64(f), true
		}
	case int:
		return int64(n), true
	case int64:
		return n, true
	}
	return 0, false
}

// GetFloat64 returns the claim key as a float64 together with true when it is
// present and numeric (float64, json.Number, or an integer type). It returns
// (0, false) otherwise.
func (m MapClaims) GetFloat64(key string) (float64, bool) {
	switch n := m[key].(type) {
	case float64:
		return n, true
	case json.Number:
		if f, err := n.Float64(); err == nil {
			return f, true
		}
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	}
	return 0, false
}

// GetBool returns the claim key as a bool together with true when it is present
// and holds a JSON boolean. It returns (false, false) otherwise.
func (m MapClaims) GetBool(key string) (bool, bool) {
	if b, ok := m[key].(bool); ok {
		return b, true
	}
	return false, false
}

// GetStringSlice returns the claim key as a slice of strings. A single JSON
// string yields a one-element slice; a JSON array yields its string elements
// (non-string elements are skipped). A missing or unsupported value yields nil.
func (m MapClaims) GetStringSlice(key string) []string {
	switch v := m[key].(type) {
	case string:
		return []string{v}
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// GetTime returns the claim key interpreted as a NumericDate (seconds since the
// Unix epoch) together with true when it is present and numeric. It returns the
// zero time and false otherwise. The returned time is in UTC.
func (m MapClaims) GetTime(key string) (time.Time, bool) {
	d, err := m.parseNumericDate(key)
	if err != nil || d == nil {
		return time.Time{}, false
	}
	return d.Time, true
}

// Set stores value under key and returns the receiver, allowing calls to be
// chained when assembling a claim set (m.Set("a", 1).Set("b", 2)).
func (m MapClaims) Set(key string, value any) MapClaims {
	m[key] = value
	return m
}

// Has reports whether the claim key is present with a non-nil value.
func (m MapClaims) Has(key string) bool {
	v, ok := m[key]
	return ok && v != nil
}
