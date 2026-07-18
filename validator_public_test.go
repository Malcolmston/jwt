package jwt

import (
	"errors"
	"testing"
	"time"
)

func TestValidatorValidateTimes(t *testing.T) {
	fixed := time.Unix(1000, 0).UTC()
	clock := ClockFunc(func() time.Time { return fixed })

	val := NewValidator(WithClock(clock), WithIssuer("iss"), WithAudience("aud"))

	good := MapClaims{
		"iss": "iss",
		"aud": "aud",
		"exp": float64(2000),
		"nbf": float64(500),
	}
	if err := val.Validate(good); err != nil {
		t.Fatalf("expected valid, got %v", err)
	}

	expired := MapClaims{"iss": "iss", "aud": "aud", "exp": float64(999)}
	if err := val.Validate(expired); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired, got %v", err)
	}

	badIss := MapClaims{"iss": "other", "aud": "aud", "exp": float64(2000)}
	if err := val.Validate(badIss); !errors.Is(err, ErrTokenInvalidIssuer) {
		t.Fatalf("expected ErrTokenInvalidIssuer, got %v", err)
	}

	badAud := MapClaims{"iss": "iss", "aud": "nope", "exp": float64(2000)}
	if err := val.Validate(badAud); !errors.Is(err, ErrTokenInvalidAudience) {
		t.Fatalf("expected ErrTokenInvalidAudience, got %v", err)
	}
}

func TestValidatorRequiredClaims(t *testing.T) {
	val := NewValidator(WithRequiredClaims("jti"))
	if err := val.Validate(MapClaims{"sub": "x"}); !errors.Is(err, ErrTokenRequiredClaimMissing) {
		t.Fatalf("expected required-claim error, got %v", err)
	}
	if err := val.Validate(MapClaims{"jti": "abc"}); err != nil {
		t.Fatalf("expected valid, got %v", err)
	}
}

func TestValidatorRegisteredClaims(t *testing.T) {
	fixed := time.Unix(1000, 0).UTC()
	val := NewValidator(WithTimeFunc(func() time.Time { return fixed }))
	rc := RegisteredClaims{
		ExpiresAt: NewNumericDate(time.Unix(500, 0)),
	}
	if err := val.Validate(rc); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired for RegisteredClaims, got %v", err)
	}
}
