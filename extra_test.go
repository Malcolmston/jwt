package jwt

import (
	"errors"
	"testing"
	"time"
)

func TestNewAndParserMethod(t *testing.T) {
	secret := []byte("k")
	tok := New(SigningMethodHS256) // empty RegisteredClaims default
	tok.Claims = RegisteredClaims{Issuer: "x", ExpiresAt: NewNumericDate(refTime.Add(time.Hour))}
	signed, err := tok.SignedString(secret)
	if err != nil {
		t.Fatal(err)
	}
	p := NewParser(WithTimeFunc(func() time.Time { return refTime }))
	if _, err := p.Parse(signed, func(*Token) (any, error) { return secret, nil }); err != nil {
		t.Fatalf("parser.Parse: %v", err)
	}
}

func TestSystemClockNow(t *testing.T) {
	before := time.Now().Add(-time.Second)
	got := systemClock{}.Now()
	if got.Before(before) {
		t.Fatalf("system clock returned stale time")
	}
}

func TestWithJSONNumber(t *testing.T) {
	secret := []byte("k")
	// A large integer exp that would lose precision as float64.
	claims := MapClaims{"exp": int64(4102444800), "n": int64(9007199254740993)}
	signed, err := Sign(claims, SigningMethodHS256, secret)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := Parse(signed, func(*Token) (any, error) { return secret, nil },
		WithClock(fixedClock{refTime}), WithJSONNumber())
	if err != nil {
		t.Fatalf("json number parse: %v", err)
	}
	mc := tok.Claims.(MapClaims)
	// exp must still validate through the json.Number path.
	if mc.GetExpirationTime() == nil {
		t.Fatal("exp not decoded")
	}
}

func TestMapClaimsAccessors(t *testing.T) {
	mc := MapClaims{
		"aud": "solo",
		"iss": "iss1",
		"sub": "sub1",
		"exp": float64(refTime.Unix()),
	}
	if got := mc.GetAudience(); len(got) != 1 || got[0] != "solo" {
		t.Fatalf("string aud: %v", got)
	}
	if mc.GetIssuer() != "iss1" || mc.GetSubject() != "sub1" {
		t.Fatal("iss/sub accessors")
	}
	if mc.GetExpirationTime() == nil {
		t.Fatal("exp accessor")
	}
	// Missing / wrong-typed claims yield zero values.
	empty := MapClaims{"iss": 123}
	if empty.GetIssuer() != "" || empty.GetAudience() != nil || empty.GetNotBefore() != nil {
		t.Fatal("expected zero values for absent/mistyped claims")
	}
	// []any audience form.
	anyAud := MapClaims{"aud": []any{"x", "y"}}
	if len(anyAud.GetAudience()) != 2 {
		t.Fatal("[]any aud")
	}
}

func TestNoneVerifyRejectsNonEmptySig(t *testing.T) {
	err := SigningMethodNoneAlg.Verify("a.b", []byte("notempty"), UnsafeAllowNoneSignatureType)
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("expected ErrSignatureInvalid, got %v", err)
	}
	err = SigningMethodNoneAlg.Verify("a.b", nil, []byte("wrong-key"))
	if !errors.Is(err, ErrNoneAlgDisallowed) {
		t.Fatalf("expected ErrNoneAlgDisallowed, got %v", err)
	}
}

func TestSignInvalidKeyTypes(t *testing.T) {
	if _, err := SigningMethodHS256.Sign("x", "not-bytes"); !errors.Is(err, ErrInvalidKeyType) {
		t.Fatalf("hmac: %v", err)
	}
	if _, err := SigningMethodRS256.Sign("x", "nope"); !errors.Is(err, ErrInvalidKeyType) {
		t.Fatalf("rsa: %v", err)
	}
	if _, err := SigningMethodPS256.Sign("x", "nope"); !errors.Is(err, ErrInvalidKeyType) {
		t.Fatalf("pss: %v", err)
	}
	if _, err := SigningMethodES256.Sign("x", "nope"); !errors.Is(err, ErrInvalidKeyType) {
		t.Fatalf("ecdsa: %v", err)
	}
	// Verify with wrong key types.
	if err := SigningMethodRS256.Verify("x", nil, "nope"); !errors.Is(err, ErrInvalidKeyType) {
		t.Fatalf("rsa verify: %v", err)
	}
	if err := SigningMethodPS256.Verify("x", nil, "nope"); !errors.Is(err, ErrInvalidKeyType) {
		t.Fatalf("pss verify: %v", err)
	}
	if err := SigningMethodES256.Verify("x", nil, "nope"); !errors.Is(err, ErrInvalidKeyType) {
		t.Fatalf("ecdsa verify: %v", err)
	}
}

func TestKeyHelperErrors(t *testing.T) {
	for _, bad := range [][]byte{[]byte("plain"), nil} {
		if _, err := ParseECPrivateKeyFromPEM(bad); err == nil {
			t.Fatal("expected error for non-PEM EC private key")
		}
		if _, err := ParseECPublicKeyFromPEM(bad); err == nil {
			t.Fatal("expected error for non-PEM EC public key")
		}
		if _, err := ParseRSAPublicKeyFromPEM(bad); err == nil {
			t.Fatal("expected error for non-PEM RSA public key")
		}
	}
}
