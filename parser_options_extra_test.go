package jwt

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

var extraTestKey = []byte("test-secret")

func extraKeyfunc(*Token) (any, error) { return extraTestKey, nil }

// paddedToken re-encodes the signature segment with '=' padding, producing a
// token that decodes identically but violates the unpadded-base64url rule.
func paddedToken(t *testing.T) string {
	t.Helper()
	signed, err := Sign(MapClaims{"sub": "x"}, SigningMethodHS256, extraTestKey)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(signed, ".")
	sig, err := DecodeSegment(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	padded := base64.URLEncoding.EncodeToString(sig)
	if !strings.Contains(padded, "=") {
		t.Fatal("expected padding in test fixture")
	}
	return parts[0] + "." + parts[1] + "." + padded
}

func TestWithStrictDecodingRejectsPadding(t *testing.T) {
	tok := paddedToken(t)

	// Default (tolerant) parser accepts the padded token.
	if _, err := Parse(tok, extraKeyfunc, WithValidMethods([]string{"HS256"})); err != nil {
		t.Fatalf("tolerant parse failed: %v", err)
	}

	// Strict decoding rejects it as malformed.
	_, err := Parse(tok, extraKeyfunc, WithValidMethods([]string{"HS256"}), WithStrictDecoding())
	if !errors.Is(err, ErrTokenMalformed) {
		t.Fatalf("expected ErrTokenMalformed, got %v", err)
	}

	// WithPaddingAllowed after WithStrictDecoding re-enables tolerance.
	_, err = Parse(tok, extraKeyfunc, WithValidMethods([]string{"HS256"}), WithStrictDecoding(), WithPaddingAllowed())
	if err != nil {
		t.Fatalf("padding-allowed override failed: %v", err)
	}
}

func TestWithoutClaimsValidation(t *testing.T) {
	claims := RegisteredClaims{
		ExpiresAt: NewNumericDate(time.Now().Add(-time.Hour)),
	}
	signed, err := Sign(claims, SigningMethodHS256, extraTestKey)
	if err != nil {
		t.Fatal(err)
	}

	// Normal parse rejects the expired token.
	var c1 RegisteredClaims
	_, err = ParseWithClaims(signed, &c1, extraKeyfunc, WithValidMethods([]string{"HS256"}))
	if !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired, got %v", err)
	}

	// With validation disabled it parses successfully.
	var c2 RegisteredClaims
	tok, err := ParseWithClaims(signed, &c2, extraKeyfunc,
		WithValidMethods([]string{"HS256"}), WithoutClaimsValidation())
	if err != nil {
		t.Fatalf("expected success with validation disabled, got %v", err)
	}
	if !tok.Valid {
		t.Fatal("token should be marked valid when claims validation is skipped")
	}
}
