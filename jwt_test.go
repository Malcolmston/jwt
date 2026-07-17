package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"
)

// fixedClock is a deterministic Clock for time-based validation tests.
type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

var refTime = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

func baseClaims() RegisteredClaims {
	return RegisteredClaims{
		Issuer:    "issuer.example",
		Subject:   "user-123",
		Audience:  ClaimStrings{"aud-a", "aud-b"},
		ExpiresAt: NewNumericDate(refTime.Add(time.Hour)),
		NotBefore: NewNumericDate(refTime.Add(-time.Minute)),
		IssuedAt:  NewNumericDate(refTime.Add(-time.Minute)),
		ID:        "jti-1",
	}
}

func TestHMACRoundTrip(t *testing.T) {
	secret := []byte("super-secret-value")
	for _, m := range []SigningMethod{SigningMethodHS256, SigningMethodHS384, SigningMethodHS512} {
		signed, err := Sign(baseClaims(), m, secret)
		if err != nil {
			t.Fatalf("%s sign: %v", m.Alg(), err)
		}
		var got RegisteredClaims
		tok, err := ParseWithClaims(signed, &got, func(*Token) (any, error) { return secret, nil },
			WithValidMethods([]string{m.Alg()}),
			WithClock(fixedClock{refTime}),
			WithAudience("aud-b"),
			WithIssuer("issuer.example"),
			WithSubject("user-123"),
			WithIssuedAt(),
			WithExpirationRequired(),
		)
		if err != nil {
			t.Fatalf("%s parse: %v", m.Alg(), err)
		}
		if !tok.Valid {
			t.Fatalf("%s: token not marked valid", m.Alg())
		}
		if got.Issuer != "issuer.example" || got.ID != "jti-1" {
			t.Fatalf("%s: claims round-trip mismatch: %+v", m.Alg(), got)
		}
	}
}

func TestRSARoundTrip(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	methods := []SigningMethod{
		SigningMethodRS256, SigningMethodRS384, SigningMethodRS512,
		SigningMethodPS256, SigningMethodPS384, SigningMethodPS512,
	}
	for _, m := range methods {
		signed, err := Sign(baseClaims(), m, priv)
		if err != nil {
			t.Fatalf("%s sign: %v", m.Alg(), err)
		}
		_, err = Parse(signed, func(*Token) (any, error) { return &priv.PublicKey, nil },
			WithValidMethods([]string{m.Alg()}), WithClock(fixedClock{refTime}))
		if err != nil {
			t.Fatalf("%s parse: %v", m.Alg(), err)
		}
	}
}

func TestECDSARoundTrip(t *testing.T) {
	cases := []struct {
		m     SigningMethod
		curve elliptic.Curve
	}{
		{SigningMethodES256, elliptic.P256()},
		{SigningMethodES384, elliptic.P384()},
		{SigningMethodES512, elliptic.P521()},
	}
	for _, c := range cases {
		priv, err := ecdsa.GenerateKey(c.curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		signed, err := Sign(baseClaims(), c.m, priv)
		if err != nil {
			t.Fatalf("%s sign: %v", c.m.Alg(), err)
		}
		// Verify fixed-width signature length: 2 * coordinate size.
		parts := strings.Split(signed, ".")
		sig, err := DecodeSegment(parts[2])
		if err != nil {
			t.Fatal(err)
		}
		want := 2 * c.m.(*SigningMethodECDSA).KeySize
		if len(sig) != want {
			t.Fatalf("%s: signature len = %d, want %d", c.m.Alg(), len(sig), want)
		}
		if _, err := Parse(signed, func(*Token) (any, error) { return &priv.PublicKey, nil },
			WithValidMethods([]string{c.m.Alg()}), WithClock(fixedClock{refTime})); err != nil {
			t.Fatalf("%s parse: %v", c.m.Alg(), err)
		}
	}
}

func TestExpiredToken(t *testing.T) {
	secret := []byte("k")
	claims := RegisteredClaims{ExpiresAt: NewNumericDate(refTime.Add(-time.Hour))}
	signed, _ := Sign(claims, SigningMethodHS256, secret)
	_, err := Parse(signed, func(*Token) (any, error) { return secret, nil },
		WithClock(fixedClock{refTime}))
	if !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired, got %v", err)
	}
	// With enough leeway the same token validates.
	_, err = Parse(signed, func(*Token) (any, error) { return secret, nil },
		WithClock(fixedClock{refTime}), WithLeeway(2*time.Hour))
	if err != nil {
		t.Fatalf("leeway should allow token: %v", err)
	}
}

func TestNotYetValid(t *testing.T) {
	secret := []byte("k")
	claims := RegisteredClaims{NotBefore: NewNumericDate(refTime.Add(time.Hour))}
	signed, _ := Sign(claims, SigningMethodHS256, secret)
	_, err := Parse(signed, func(*Token) (any, error) { return secret, nil },
		WithClock(fixedClock{refTime}))
	if !errors.Is(err, ErrTokenNotValidYet) {
		t.Fatalf("expected ErrTokenNotValidYet, got %v", err)
	}
}

func TestIssuedAtFuture(t *testing.T) {
	secret := []byte("k")
	claims := RegisteredClaims{IssuedAt: NewNumericDate(refTime.Add(time.Hour))}
	signed, _ := Sign(claims, SigningMethodHS256, secret)
	_, err := Parse(signed, func(*Token) (any, error) { return secret, nil },
		WithClock(fixedClock{refTime}), WithIssuedAt())
	if !errors.Is(err, ErrTokenUsedBeforeIssued) {
		t.Fatalf("expected ErrTokenUsedBeforeIssued, got %v", err)
	}
}

func TestTamperedToken(t *testing.T) {
	secret := []byte("k")
	signed, _ := Sign(baseClaims(), SigningMethodHS256, secret)
	parts := strings.Split(signed, ".")
	// Modify the payload but keep the original signature.
	tampered := parts[0] + "." + EncodeSegment([]byte(`{"iss":"attacker"}`)) + "." + parts[2]
	_, err := Parse(tampered, func(*Token) (any, error) { return secret, nil },
		WithClock(fixedClock{refTime}))
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("expected ErrSignatureInvalid, got %v", err)
	}
}

func TestAlgMismatchRejected(t *testing.T) {
	secret := []byte("k")
	signed, _ := Sign(baseClaims(), SigningMethodHS256, secret)
	_, err := Parse(signed, func(*Token) (any, error) { return secret, nil },
		WithValidMethods([]string{"HS384"}), WithClock(fixedClock{refTime}))
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("expected rejection for disallowed alg, got %v", err)
	}
}

func TestWrongKeyType(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	// Sign HS256 but hand the verifier an RSA public key.
	signed, _ := Sign(baseClaims(), SigningMethodHS256, []byte("k"))
	_, err := Parse(signed, func(*Token) (any, error) { return &priv.PublicKey, nil },
		WithClock(fixedClock{refTime}))
	if !errors.Is(err, ErrInvalidKeyType) {
		t.Fatalf("expected ErrInvalidKeyType, got %v", err)
	}
}

func TestAudienceAndIssuerValidation(t *testing.T) {
	secret := []byte("k")
	signed, _ := Sign(baseClaims(), SigningMethodHS256, secret)

	_, err := Parse(signed, func(*Token) (any, error) { return secret, nil },
		WithClock(fixedClock{refTime}), WithAudience("nope"))
	if !errors.Is(err, ErrTokenInvalidAudience) {
		t.Fatalf("expected ErrTokenInvalidAudience, got %v", err)
	}

	_, err = Parse(signed, func(*Token) (any, error) { return secret, nil },
		WithClock(fixedClock{refTime}), WithIssuer("someone-else"))
	if !errors.Is(err, ErrTokenInvalidIssuer) {
		t.Fatalf("expected ErrTokenInvalidIssuer, got %v", err)
	}

	_, err = Parse(signed, func(*Token) (any, error) { return secret, nil },
		WithClock(fixedClock{refTime}), WithSubject("someone-else"))
	if !errors.Is(err, ErrTokenInvalidSubject) {
		t.Fatalf("expected ErrTokenInvalidSubject, got %v", err)
	}
}

func TestExpirationRequired(t *testing.T) {
	secret := []byte("k")
	signed, _ := Sign(RegisteredClaims{Issuer: "x"}, SigningMethodHS256, secret)
	_, err := Parse(signed, func(*Token) (any, error) { return secret, nil },
		WithClock(fixedClock{refTime}), WithExpirationRequired())
	if !errors.Is(err, ErrTokenRequiredClaimMissing) {
		t.Fatalf("expected ErrTokenRequiredClaimMissing, got %v", err)
	}
}

func TestMalformedToken(t *testing.T) {
	secret := []byte("k")
	for _, bad := range []string{"", "onlyonepart", "a.b", "a.b.c.d"} {
		_, err := Parse(bad, func(*Token) (any, error) { return secret, nil })
		if !errors.Is(err, ErrTokenMalformed) {
			t.Fatalf("input %q: expected ErrTokenMalformed, got %v", bad, err)
		}
	}
	// Valid shape but invalid base64 in the header.
	_, err := Parse("!!!.###.$$$", func(*Token) (any, error) { return secret, nil })
	if !errors.Is(err, ErrTokenMalformed) {
		t.Fatalf("expected ErrTokenMalformed for bad base64, got %v", err)
	}
}

func TestNoneAlgorithm(t *testing.T) {
	signed, err := Sign(RegisteredClaims{Issuer: "x"}, SigningMethodNoneAlg, UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}
	// Rejected by default.
	if _, err := Parse(signed, func(*Token) (any, error) { return UnsafeAllowNoneSignatureType, nil }); !errors.Is(err, ErrNoneAlgDisallowed) {
		t.Fatalf("expected ErrNoneAlgDisallowed, got %v", err)
	}
	// Accepted with WithAllowNone and the magic key.
	if _, err := Parse(signed, func(*Token) (any, error) { return UnsafeAllowNoneSignatureType, nil },
		WithAllowNone(), WithClock(fixedClock{refTime})); err != nil {
		t.Fatalf("none with allow: %v", err)
	}
	// Signing none without the magic key fails.
	if _, err := Sign(RegisteredClaims{}, SigningMethodNoneAlg, []byte("x")); !errors.Is(err, ErrNoneAlgDisallowed) {
		t.Fatalf("expected ErrNoneAlgDisallowed on sign, got %v", err)
	}
}

func TestKIDSelection(t *testing.T) {
	keys := map[string][]byte{"k1": []byte("secret-one"), "k2": []byte("secret-two")}
	tok := NewWithClaims(SigningMethodHS256, baseClaims()).SetKID("k2")
	signed, err := tok.SignedString(keys["k2"])
	if err != nil {
		t.Fatal(err)
	}
	_, err = Parse(signed, func(tk *Token) (any, error) {
		kid, _ := tk.Header["kid"].(string)
		return keys[kid], nil
	}, WithClock(fixedClock{refTime}))
	if err != nil {
		t.Fatalf("kid parse: %v", err)
	}
}

func TestMapClaims(t *testing.T) {
	secret := []byte("k")
	claims := MapClaims{
		"iss":  "m-issuer",
		"aud":  []string{"one", "two"},
		"exp":  float64(refTime.Add(time.Hour).Unix()),
		"role": "admin",
	}
	signed, err := Sign(claims, SigningMethodHS256, secret)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := Parse(signed, func(*Token) (any, error) { return secret, nil },
		WithClock(fixedClock{refTime}), WithAudience("two"), WithIssuer("m-issuer"))
	if err != nil {
		t.Fatalf("map parse: %v", err)
	}
	mc := tok.Claims.(MapClaims)
	if mc["role"] != "admin" {
		t.Fatalf("custom claim lost: %v", mc["role"])
	}
}

// customClaims exercises using an arbitrary struct as claims via embedding.
type customClaims struct {
	Role  string `json:"role"`
	Email string `json:"email"`
	RegisteredClaims
}

func TestCustomStructClaims(t *testing.T) {
	secret := []byte("k")
	in := customClaims{
		Role:             "editor",
		Email:            "a@b.com",
		RegisteredClaims: baseClaims(),
	}
	signed, err := Sign(in, SigningMethodHS256, secret)
	if err != nil {
		t.Fatal(err)
	}
	var out customClaims
	if _, err := ParseWithClaims(signed, &out, func(*Token) (any, error) { return secret, nil },
		WithClock(fixedClock{refTime})); err != nil {
		t.Fatalf("custom parse: %v", err)
	}
	if out.Role != "editor" || out.Email != "a@b.com" || out.Issuer != "issuer.example" {
		t.Fatalf("custom struct round-trip mismatch: %+v", out)
	}
}

func TestBase64URLEdgeCases(t *testing.T) {
	// Bytes that produce '+' and '/' in standard base64 must use '-' and '_'.
	raw := []byte{0xfb, 0xff, 0xbf, 0x00, 0x10, 0x83}
	enc := EncodeSegment(raw)
	if strings.ContainsAny(enc, "+/=") {
		t.Fatalf("base64url output contains disallowed chars: %q", enc)
	}
	back, err := DecodeSegment(enc)
	if err != nil {
		t.Fatal(err)
	}
	if string(back) != string(raw) {
		t.Fatalf("round-trip mismatch")
	}
	// Padded input is tolerated on decode.
	if _, err := DecodeSegment("YQ=="); err != nil {
		t.Fatalf("padded decode should be tolerated: %v", err)
	}
	// Empty segment decodes to empty bytes.
	if b, err := DecodeSegment(""); err != nil || len(b) != 0 {
		t.Fatalf("empty decode: %v %v", b, err)
	}
}

func TestClaimStringsSingleString(t *testing.T) {
	// A JWT whose aud is a bare string must decode to a one-element ClaimStrings.
	secret := []byte("k")
	signed := mustSignRawAud(t, secret, `"single-aud"`)
	_, err := Parse(signed, func(*Token) (any, error) { return secret, nil },
		WithClock(fixedClock{refTime}), WithAudience("single-aud"))
	if err != nil {
		t.Fatalf("single-string aud: %v", err)
	}
}

// mustSignRawAud crafts and HS256-signs a token whose aud field is the raw JSON
// audValue, to exercise ClaimStrings decoding of a bare string.
func mustSignRawAud(t *testing.T, secret []byte, audValue string) string {
	t.Helper()
	header := EncodeSegment([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := EncodeSegment([]byte(`{"aud":` + audValue + `}`))
	signingInput := header + "." + payload
	sig, err := SigningMethodHS256.Sign(signingInput, secret)
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + EncodeSegment(sig)
}

func TestPEMKeyHelpers(t *testing.T) {
	// RSA PKCS#8 private + PKIX public.
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaPrivDER, _ := x509.MarshalPKCS8PrivateKey(rsaKey)
	rsaPrivPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rsaPrivDER})
	rsaPubDER, _ := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	rsaPubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: rsaPubDER})

	if _, err := ParseRSAPrivateKeyFromPEM(rsaPrivPEM); err != nil {
		t.Fatalf("rsa priv pem: %v", err)
	}
	if _, err := ParseRSAPublicKeyFromPEM(rsaPubPEM); err != nil {
		t.Fatalf("rsa pub pem: %v", err)
	}

	// EC SEC1 private + PKIX public.
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecPrivDER, _ := x509.MarshalECPrivateKey(ecKey)
	ecPrivPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecPrivDER})
	ecPubDER, _ := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	ecPubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: ecPubDER})

	if _, err := ParseECPrivateKeyFromPEM(ecPrivPEM); err != nil {
		t.Fatalf("ec priv pem: %v", err)
	}
	if _, err := ParseECPublicKeyFromPEM(ecPubPEM); err != nil {
		t.Fatalf("ec pub pem: %v", err)
	}

	// A full RS256 sign/verify through PEM-parsed keys.
	signed, err := Sign(baseClaims(), SigningMethodRS256, rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := ParseRSAPublicKeyFromPEM(rsaPubPEM)
	if _, err := Parse(signed, func(*Token) (any, error) { return pub, nil },
		WithClock(fixedClock{refTime}), WithValidMethods([]string{"RS256"})); err != nil {
		t.Fatalf("pem round-trip: %v", err)
	}

	// Non-PEM input is rejected.
	if _, err := ParseRSAPrivateKeyFromPEM([]byte("not pem")); !errors.Is(err, ErrInvalidKeyType) {
		t.Fatalf("expected ErrInvalidKeyType, got %v", err)
	}
}

func TestUnavailableSigningMethod(t *testing.T) {
	header := EncodeSegment([]byte(`{"alg":"XX999","typ":"JWT"}`))
	payload := EncodeSegment([]byte(`{"iss":"x"}`))
	token := header + "." + payload + "." + EncodeSegment([]byte("sig"))
	_, err := Parse(token, func(*Token) (any, error) { return []byte("k"), nil })
	if !errors.Is(err, ErrSigningMethodUnavailable) {
		t.Fatalf("expected ErrSigningMethodUnavailable, got %v", err)
	}
}

func TestNumericDateEncoding(t *testing.T) {
	d := NewNumericDate(refTime)
	b, err := d.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "1767268800" {
		t.Fatalf("numeric date encoding = %s", b)
	}
	var d2 NumericDate
	if err := d2.UnmarshalJSON([]byte("1767268800.5")); err != nil {
		t.Fatal(err)
	}
	if d2.Unix() != 1767268800 {
		t.Fatalf("numeric date decode: %v", d2.Time)
	}
	if NewNumericDate(time.Time{}) != nil {
		t.Fatalf("zero time should yield nil NumericDate")
	}
}

func TestGetAlgorithms(t *testing.T) {
	algs := GetAlgorithms()
	want := []string{"HS256", "RS256", "PS256", "ES256", "ES512", "none"}
	for _, w := range want {
		if !contains(algs, w) {
			t.Fatalf("expected %s to be registered; have %v", w, algs)
		}
	}
	if GetSigningMethod("HS256") == nil {
		t.Fatal("GetSigningMethod(HS256) nil")
	}
	if GetSigningMethod("bogus") != nil {
		t.Fatal("GetSigningMethod(bogus) should be nil")
	}
}
