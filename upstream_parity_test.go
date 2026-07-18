package jwt

// Upstream-parity tests. Each TestParity* function encodes a concrete
// known-answer vector taken from the test suite of the library this package
// mirrors — auth0/node-jsonwebtoken (https://github.com/auth0/node-jsonwebtoken,
// test/*.tests.js) — and asserts the equivalent behavior against this package's
// real, exported Go API. Vectors that assert a specific serialized token
// (e.g. the HS256 tokens embedded in test/verify.tests.js) are reproduced
// verbatim so the assertions are deterministic and independent of wall-clock
// time via an injected clock.

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

// fixedClockAt returns a Clock pinned to the given Unix second, matching how
// node-jsonwebtoken's tests use sinon.useFakeTimers / clockTimestamp.
func fixedClockAt(unixSec int64) Clock {
	return ClockFunc(func() time.Time { return time.Unix(unixSec, 0) })
}

// Known HS256 token from test/verify.tests.js "secret or token as callback"
// and "expiration": payload {foo:'bar', iat:1437018582, exp:1437018592},
// signed with the HMAC secret "key".
const upstreamHS256Token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
	"eyJmb28iOiJiYXIiLCJpYXQiOjE0MzcwMTg1ODIsImV4cCI6MTQzNzAxODU5Mn0." +
	"3aR3vocmgRpG05rsI9MpR6z2T_BGtMQaPq2YR6QaroU"

// Known HS256 token from test/verify.tests.js "maxAge and clockTimestamp":
// payload {foo:'bar', iat:1437018582, exp:1437018800}, secret "key".
const upstreamHS256TokenLongExp = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
	"eyJmb28iOiJiYXIiLCJpYXQiOjE0MzcwMTg1ODIsImV4cCI6MTQzNzAxODgwMH0." +
	"AVOsNC7TiT-XVSpCpkwB1240izzCIJ33Lp07gjnXVpA"

// upstreamWrongAlgToken is the HS256 token from test/wrong_alg.tests.js.
const upstreamWrongAlgToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9." +
	"eyJmb28iOiJiYXIiLCJpYXQiOjE0MjY1NDY5MTl9." +
	"ETgkTn8BaxIX4YqvUWVFPmum3moNZ7oARZtSBXb_vP4"

func keyFuncBytes(secret string) Keyfunc {
	return func(*Token) (any, error) { return []byte(secret), nil }
}

// TestParityHS256Roundtrip mirrors test/jwt.hs.tests.js "with a token signed
// using HS256": sign {foo:'bar'} with secret 'shhhhhh', get a 3-part token,
// verify and read foo; an invalid secret must fail.
func TestParityHS256Roundtrip(t *testing.T) {
	secret := "shhhhhh"
	tok, err := Sign(MapClaims{"foo": "bar"}, SigningMethodHS256, []byte(secret))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if got := len(strings.Split(tok, ".")); got != 3 {
		t.Fatalf("token has %d parts, want 3", got)
	}
	parsed, err := Parse(tok, keyFuncBytes(secret))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if v, _ := parsed.Claims.(MapClaims)["foo"].(string); v != "bar" {
		t.Fatalf("foo = %q, want bar", v)
	}

	// invalid secret -> signature invalid
	if _, err := Parse(tok, keyFuncBytes("invalid secret")); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("invalid secret err = %v, want ErrSignatureInvalid", err)
	}
}

// TestParityHS256KnownToken mirrors test/verify.tests.js "without callback":
// the fixed token decodes to {foo:'bar', iat:1437018582, exp:1437018592}.
func TestParityHS256KnownToken(t *testing.T) {
	parsed, err := Parse(upstreamHS256Token, keyFuncBytes("key"),
		WithValidMethods([]string{"HS256"}),
		WithClock(fixedClockAt(1437018585))) // before exp
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	mc := parsed.Claims.(MapClaims)
	if mc["foo"] != "bar" {
		t.Fatalf("foo = %v", mc["foo"])
	}
	if iat, _ := mc.GetInt64("iat"); iat != 1437018582 {
		t.Fatalf("iat = %d, want 1437018582", iat)
	}
	if exp, _ := mc.GetInt64("exp"); exp != 1437018592 {
		t.Fatalf("exp = %d, want 1437018592", exp)
	}
}

// TestParityExpired mirrors test/verify.tests.js "should error on expired
// token": at iat+58s the token is expired.
func TestParityExpired(t *testing.T) {
	_, err := Parse(upstreamHS256Token, keyFuncBytes("key"),
		WithValidMethods([]string{"HS256"}),
		WithClock(fixedClockAt(1437018650)))
	if !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("err = %v, want ErrTokenExpired", err)
	}
}

// TestParityClockTolerance mirrors test/verify.tests.js "should not error on
// expired token within clockTolerance interval": exp+2s with 5s leeway passes,
// but with no leeway it fails.
func TestParityClockTolerance(t *testing.T) {
	// exp is 1437018592; now is 1437018594 (exp+2s).
	if _, err := Parse(upstreamHS256Token, keyFuncBytes("key"),
		WithClock(fixedClockAt(1437018594)), WithLeeway(5*time.Second)); err != nil {
		t.Fatalf("within tolerance should pass, got %v", err)
	}
	if _, err := Parse(upstreamHS256Token, keyFuncBytes("key"),
		WithClock(fixedClockAt(1437018594))); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("without tolerance err = %v, want ErrTokenExpired", err)
	}
}

// TestParityIgnoreExpiration mirrors test/jwt.hs.tests.js "should NOT return an
// error ... with ignoreExpiration": an expired token verifies (and foo is
// readable) when expiration is ignored.
func TestParityIgnoreExpiration(t *testing.T) {
	parsed, err := Parse(upstreamHS256Token, keyFuncBytes("key"),
		WithValidMethods([]string{"HS256"}),
		WithClock(fixedClockAt(1437018650)), // well past exp
		WithIgnoreExpiration())
	if err != nil {
		t.Fatalf("ignoreExpiration should verify, got %v", err)
	}
	if parsed.Claims.(MapClaims)["foo"] != "bar" {
		t.Fatalf("foo not readable after ignoreExpiration")
	}
}

// TestParityIgnoreNotBefore checks the counterpart of node's ignoreNotBefore:
// a token whose nbf is in the future is rejected by default but accepted when
// the not-before check is ignored.
func TestParityIgnoreNotBefore(t *testing.T) {
	now := time.Unix(1437018585, 0)
	claims := RegisteredClaims{
		Subject:   "sub",
		NotBefore: NewNumericDate(now.Add(time.Hour)), // not valid yet
	}
	tok, err := Sign(claims, SigningMethodHS256, []byte("key"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := Parse(tok, keyFuncBytes("key"), WithClock(fixedClockAt(1437018585))); !errors.Is(err, ErrTokenNotValidYet) {
		t.Fatalf("default err = %v, want ErrTokenNotValidYet", err)
	}
	if _, err := Parse(tok, keyFuncBytes("key"),
		WithClock(fixedClockAt(1437018585)), WithIgnoreNotBefore()); err != nil {
		t.Fatalf("ignoreNotBefore should verify, got %v", err)
	}
}

// TestParityMaxAgeNotMorePermissiveThanExp mirrors test/verify.tests.js
// "option: maxAge and clockTimestamp — cannot be more permissive than
// expiration": even with a 1000y maxAge, an expired token is rejected.
func TestParityMaxAgeNotMorePermissiveThanExp(t *testing.T) {
	// token exp = 1437018800; now = 1437018900 (past exp); maxAge huge.
	_, err := Parse(upstreamHS256TokenLongExp, keyFuncBytes("key"),
		WithValidMethods([]string{"HS256"}),
		WithClock(fixedClockAt(1437018900)),
		WithMaxTokenAge(200*365*24*time.Hour)) // huge, but within time.Duration range
	if !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("err = %v, want ErrTokenExpired", err)
	}
}

// TestParityWrongAlg mirrors test/wrong_alg.tests.js: an HS256 token must be
// rejected when the accepted-algorithm whitelist is RS256 or HS384.
func TestParityWrongAlg(t *testing.T) {
	for _, alg := range []string{"RS256", "HS384", "PS256"} {
		_, err := Parse(upstreamWrongAlgToken, keyFuncBytes("secret"),
			WithValidMethods([]string{alg}))
		if err == nil {
			t.Fatalf("alg whitelist %q accepted an HS256 token", alg)
		}
	}
}

// TestParityAlgConfusionRSAasHMAC mirrors test/jwt.malicious.tests.js: an
// attacker signs HS256 using an RSA public key's PEM bytes as the HMAC secret;
// a verifier that resolves the RSA *public key* for that token must refuse to
// treat it as an HMAC secret ("must be a symmetric key"). This package closes
// the attack by type-asserting the key inside the HMAC method.
func TestParityAlgConfusionRSAasHMAC(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	pub := &priv.PublicKey
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	// Attacker forges an HS256 token using the PEM public key bytes as secret.
	forged, err := Sign(MapClaims{"foo": "bar"}, SigningMethodHS256, pubPEM)
	if err != nil {
		t.Fatalf("forge: %v", err)
	}

	// Victim accepts both RS256 and HS256, and resolves the RSA public key.
	_, err = Parse(forged, func(*Token) (any, error) { return pub, nil },
		WithValidMethods([]string{"RS256", "HS256"}))
	if err == nil {
		t.Fatal("algorithm-confusion token was accepted")
	}
	if !errors.Is(err, ErrInvalidKeyType) {
		t.Fatalf("err = %v, want ErrInvalidKeyType (key must be symmetric)", err)
	}
}

// TestParityRS256Roundtrip mirrors test/rsa-public-key.tests.js / issue_70:
// sign RS256 with an RSA private key, verify with the public key; a tampered
// token must fail.
func TestParityRS256Roundtrip(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tok, err := Sign(MapClaims{"foo": "bar"}, SigningMethodRS256, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	parsed, err := Parse(tok, func(*Token) (any, error) { return &priv.PublicKey, nil },
		WithValidMethods([]string{"RS256"}))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if parsed.Claims.(MapClaims)["foo"] != "bar" {
		t.Fatalf("foo mismatch")
	}
	// Tamper the payload; signature must fail.
	parts := strings.Split(tok, ".")
	parts[1] = EncodeSegment([]byte(`{"foo":"evil"}`))
	if _, err := Parse(strings.Join(parts, "."), func(*Token) (any, error) { return &priv.PublicKey, nil },
		WithValidMethods([]string{"RS256"})); err == nil {
		t.Fatal("tampered RS256 token verified")
	}
}

// TestParityES256Roundtrip mirrors test/schema.tests.js ES256 signing: sign and
// verify over a P-256 key.
func TestParityES256Roundtrip(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tok, err := Sign(MapClaims{"foo": "bar"}, SigningMethodES256, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := Parse(tok, func(*Token) (any, error) { return &priv.PublicKey, nil },
		WithValidMethods([]string{"ES256"})); err != nil {
		t.Fatalf("verify: %v", err)
	}
	// Verifying an ES256 token with an RSA key must be refused, not crash.
	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, err := Parse(tok, func(*Token) (any, error) { return &rsaPriv.PublicKey, nil },
		WithValidMethods([]string{"ES256"})); !errors.Is(err, ErrInvalidKeyType) {
		t.Fatalf("EC token with RSA key err = %v, want ErrInvalidKeyType", err)
	}
}

// TestParitySubject mirrors test/claim-sub.tests.js: verifying with a subject
// option succeeds when sub matches and fails otherwise.
func TestParitySubject(t *testing.T) {
	tok, err := Sign(RegisteredClaims{Subject: "foo"}, SigningMethodHS256, []byte("secret"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	// matching subject verifies and sub is readable
	var out RegisteredClaims
	if _, err := ParseWithClaims(tok, &out, keyFuncBytes("secret"), WithSubject("foo")); err != nil {
		t.Fatalf("matching subject: %v", err)
	}
	if out.Subject != "foo" {
		t.Fatalf("sub = %q, want foo", out.Subject)
	}
	// wrong subject -> invalid subject
	if _, err := ParseWithClaims(tok, &RegisteredClaims{}, keyFuncBytes("secret"), WithSubject("bar")); !errors.Is(err, ErrTokenInvalidSubject) {
		t.Fatalf("wrong subject err = %v, want ErrTokenInvalidSubject", err)
	}
	// missing sub but subject required -> invalid subject
	tok2, _ := Sign(RegisteredClaims{}, SigningMethodHS256, []byte("secret"))
	if _, err := ParseWithClaims(tok2, &RegisteredClaims{}, keyFuncBytes("secret"), WithSubject("foo")); !errors.Is(err, ErrTokenInvalidSubject) {
		t.Fatalf("missing sub err = %v, want ErrTokenInvalidSubject", err)
	}
}

// TestParityAudience mirrors node's aud handling: a token whose aud contains
// the expected value verifies; otherwise ErrTokenInvalidAudience.
func TestParityAudience(t *testing.T) {
	claims := RegisteredClaims{Audience: ClaimStrings{"urn:a", "urn:b"}}
	tok, _ := Sign(claims, SigningMethodHS256, []byte("secret"))
	if _, err := ParseWithClaims(tok, &RegisteredClaims{}, keyFuncBytes("secret"), WithAudience("urn:a")); err != nil {
		t.Fatalf("matching aud: %v", err)
	}
	if _, err := ParseWithClaims(tok, &RegisteredClaims{}, keyFuncBytes("secret"), WithAudience("urn:c")); !errors.Is(err, ErrTokenInvalidAudience) {
		t.Fatalf("wrong aud err = %v, want ErrTokenInvalidAudience", err)
	}
}

// TestParityIssuer mirrors node's issuer option handling.
func TestParityIssuer(t *testing.T) {
	tok, _ := Sign(RegisteredClaims{Issuer: "auth.example.com"}, SigningMethodHS256, []byte("secret"))
	if _, err := ParseWithClaims(tok, &RegisteredClaims{}, keyFuncBytes("secret"), WithIssuer("auth.example.com")); err != nil {
		t.Fatalf("matching iss: %v", err)
	}
	if _, err := ParseWithClaims(tok, &RegisteredClaims{}, keyFuncBytes("secret"), WithIssuer("evil.example.com")); !errors.Is(err, ErrTokenInvalidIssuer) {
		t.Fatalf("wrong iss err = %v, want ErrTokenInvalidIssuer", err)
	}
}

// TestParityNoneDefaultRejected mirrors test/verify.tests.js "should not be
// able to verify unsigned token": an alg:none token is rejected unless "none"
// is explicitly opted into (WithAllowNone plus the sentinel key).
func TestParityNoneDefaultRejected(t *testing.T) {
	tok, err := New(SigningMethodNoneAlg).SignedString(UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign none: %v", err)
	}
	// Providing a secret without opting into none must reject.
	if _, err := Parse(tok, keyFuncBytes("secret")); !errors.Is(err, ErrNoneAlgDisallowed) {
		t.Fatalf("default none err = %v, want ErrNoneAlgDisallowed", err)
	}
	// Opt in: WithAllowNone + sentinel key verifies.
	if _, err := Parse(tok, func(*Token) (any, error) { return UnsafeAllowNoneSignatureType, nil }, WithAllowNone()); err != nil {
		t.Fatalf("opted-in none: %v", err)
	}
}

// TestParityEncodingUTF8 mirrors test/encoding.tests.js: multibyte claim values
// round-trip through sign/verify unchanged.
func TestParityEncodingUTF8(t *testing.T) {
	for _, name := range []string{"José", "測試"} {
		tok, err := Sign(MapClaims{"name": name}, SigningMethodHS256, []byte("shhhhh"))
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		parsed, err := Parse(tok, keyFuncBytes("shhhhh"))
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		if parsed.Claims.(MapClaims)["name"] != name {
			t.Fatalf("name = %v, want %q", parsed.Claims.(MapClaims)["name"], name)
		}
	}
}

// TestParityTrailingSpace mirrors test/jwt.hs.tests.js "should fail verification
// gracefully with trailing space": a token with a trailing space is malformed.
func TestParityTrailingSpace(t *testing.T) {
	tok, _ := Sign(MapClaims{"foo": "bar"}, SigningMethodHS256, []byte("shhhhhh"))
	if _, err := Parse(tok+" ", keyFuncBytes("shhhhhh")); !errors.Is(err, ErrTokenMalformed) {
		t.Fatalf("trailing-space err = %v, want ErrTokenMalformed", err)
	}
}

// TestParityCustomHeader mirrors test/set_headers.tests.js: a custom JOSE header
// set before signing is present after decoding.
func TestParityCustomHeader(t *testing.T) {
	tok, err := NewWithClaims(SigningMethodHS256, MapClaims{"foo": 123}).
		SetHeader("foo", "bar").SignedString([]byte("123"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	parsed, _, err := ParseUnverified(tok, MapClaims{})
	if err != nil {
		t.Fatalf("parse unverified: %v", err)
	}
	if parsed.HeaderString("foo") != "bar" {
		t.Fatalf("header foo = %q, want bar", parsed.HeaderString("foo"))
	}
}

// TestParityMissingKeyRejected mirrors test/undefined_secretOrPublickey.tests.js:
// verifying with no usable key must fail rather than accept the token.
func TestParityMissingKeyRejected(t *testing.T) {
	if _, err := Parse(upstreamHS256Token, func(*Token) (any, error) { return nil, nil },
		WithoutClaimsValidation()); err == nil {
		t.Fatal("token verified with a nil key")
	}
}
