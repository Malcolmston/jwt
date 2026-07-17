package jwt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"
)

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// ---- EdDSA ------------------------------------------------------------------

func TestEdDSARoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := Sign(baseClaims(), SigningMethodEdDSA, priv)
	if err != nil {
		t.Fatalf("eddsa sign: %v", err)
	}
	tok, err := Parse(signed, func(*Token) (any, error) { return pub, nil },
		WithValidMethods([]string{"EdDSA"}), WithClock(fixedClock{refTime}))
	if err != nil {
		t.Fatalf("eddsa parse: %v", err)
	}
	if !tok.Valid || tok.Method.Alg() != "EdDSA" {
		t.Fatalf("eddsa token not valid: %+v", tok)
	}
}

func TestEdDSAWrongKeyType(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	// Sign with a non-ed25519 type.
	if _, err := SigningMethodEdDSA.Sign("x", "nope"); !errors.Is(err, ErrInvalidKeyType) {
		t.Fatalf("sign wrong type: %v", err)
	}
	// Verify with a non-ed25519 type (alg confusion defense).
	if err := SigningMethodEdDSA.Verify("x", nil, &rsa.PublicKey{}); !errors.Is(err, ErrInvalidKeyType) {
		t.Fatalf("verify wrong type: %v", err)
	}
	// A tampered signature fails.
	sig, _ := SigningMethodEdDSA.Sign("a.b", priv)
	sig[0] ^= 0xff
	if err := SigningMethodEdDSA.Verify("a.b", sig, priv.Public().(ed25519.PublicKey)); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("expected ErrSignatureInvalid, got %v", err)
	}
}

func TestEdPEMHelpers(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	privDER, _ := x509.MarshalPKCS8PrivateKey(priv)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	pubDER, _ := x509.MarshalPKIXPublicKey(pub)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	gotPriv, err := ParseEdPrivateKeyFromPEM(privPEM)
	if err != nil {
		t.Fatalf("ed priv pem: %v", err)
	}
	gotPub, err := ParseEdPublicKeyFromPEM(pubPEM)
	if err != nil {
		t.Fatalf("ed pub pem: %v", err)
	}
	signed, _ := Sign(baseClaims(), SigningMethodEdDSA, gotPriv)
	if _, err := Parse(signed, func(*Token) (any, error) { return gotPub, nil },
		WithValidMethods([]string{"EdDSA"}), WithClock(fixedClock{refTime})); err != nil {
		t.Fatalf("ed pem round-trip: %v", err)
	}
	if _, err := ParseEdPrivateKeyFromPEM([]byte("nope")); !errors.Is(err, ErrInvalidKeyType) {
		t.Fatalf("bad ed priv pem: %v", err)
	}
	if _, err := ParseEdPublicKeyFromPEM([]byte("nope")); err == nil {
		t.Fatal("expected error for bad ed pub pem")
	}
}

// ---- JWK / JWKS -------------------------------------------------------------

func TestJWKThumbprint(t *testing.T) {
	// Known answer: the SHA-256 thumbprint (RFC 7638) of an oct key is computed
	// over the canonical JSON {"k":"<k>","kty":"oct"}. This pins both the member
	// ordering and the exact serialization.
	jwk, err := ParseJWK([]byte(`{"kty":"oct","kid":"ignored","use":"sig","k":"AQAB"}`))
	if err != nil {
		t.Fatalf("parse jwk: %v", err)
	}
	tp, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	const want = "8uBm1Oeri9AB8y3VS0WbdSfBWsS34Z45nVhm9v0yh-k"
	if got := b64u(tp); got != want {
		t.Fatalf("oct thumbprint = %q, want %q", got, want)
	}

	// Thumbprint ignores non-canonical members (kid, use, alg): two JWKs with
	// the same key material but different metadata share a thumbprint, while a
	// different key yields a different one.
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	ne := fmt.Sprintf(`"n":%q,"e":%q`, b64u(priv.N.Bytes()), b64u(big.NewInt(int64(priv.E)).Bytes()))
	a, _ := ParseJWK([]byte(fmt.Sprintf(`{"kty":"RSA","kid":"a","alg":"RS256",%s}`, ne)))
	b, _ := ParseJWK([]byte(fmt.Sprintf(`{"kty":"RSA","kid":"b","use":"sig",%s}`, ne)))
	ta, _ := a.Thumbprint(crypto.SHA256)
	tb, _ := b.Thumbprint(crypto.SHA256)
	if b64u(ta) != b64u(tb) {
		t.Fatal("thumbprint should ignore kid/use/alg")
	}
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	c, _ := ParseJWK([]byte(fmt.Sprintf(`{"kty":"RSA","n":%q,"e":"AQAB"}`, b64u(other.N.Bytes()))))
	tc, _ := c.Thumbprint(crypto.SHA256)
	if b64u(ta) == b64u(tc) {
		t.Fatal("different keys must have different thumbprints")
	}
}

func TestJWKRSARoundTrip(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwkJSON := fmt.Sprintf(`{"kty":"RSA","kid":"r1","alg":"RS256","n":%q,"e":%q}`,
		b64u(priv.N.Bytes()), b64u(big.NewInt(int64(priv.E)).Bytes()))
	jwk, err := ParseJWK([]byte(jwkJSON))
	if err != nil {
		t.Fatalf("parse rsa jwk: %v", err)
	}
	pub, ok := jwk.Key.(*rsa.PublicKey)
	if !ok || pub.N.Cmp(priv.N) != 0 {
		t.Fatalf("rsa jwk key mismatch")
	}
	signed, _ := Sign(baseClaims(), SigningMethodRS256, priv)
	if _, err := Parse(signed, func(*Token) (any, error) { return jwk.Key, nil },
		WithValidMethods([]string{"RS256"}), WithClock(fixedClock{refTime})); err != nil {
		t.Fatalf("rsa jwk verify: %v", err)
	}
}

func ecJWK(t *testing.T, priv *ecdsa.PrivateKey, crv, kid string, includePriv bool) string {
	t.Helper()
	size := (priv.Curve.Params().BitSize + 7) / 8
	x := make([]byte, size)
	y := make([]byte, size)
	priv.X.FillBytes(x)
	priv.Y.FillBytes(y)
	if includePriv {
		d := make([]byte, size)
		priv.D.FillBytes(d)
		return fmt.Sprintf(`{"kty":"EC","crv":%q,"kid":%q,"x":%q,"y":%q,"d":%q}`, crv, kid, b64u(x), b64u(y), b64u(d))
	}
	return fmt.Sprintf(`{"kty":"EC","crv":%q,"kid":%q,"x":%q,"y":%q}`, crv, kid, b64u(x), b64u(y))
}

func TestJWKECRoundTrip(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// public JWK
	pubJWK, err := ParseJWK([]byte(ecJWK(t, priv, "P-256", "e1", false)))
	if err != nil {
		t.Fatalf("parse ec pub jwk: %v", err)
	}
	if _, ok := pubJWK.Key.(*ecdsa.PublicKey); !ok {
		t.Fatal("expected *ecdsa.PublicKey")
	}
	// private JWK
	privJWK, err := ParseJWK([]byte(ecJWK(t, priv, "P-256", "e1", true)))
	if err != nil {
		t.Fatalf("parse ec priv jwk: %v", err)
	}
	if !privJWK.IsPrivate() {
		t.Fatal("expected private EC jwk")
	}
	signed, _ := Sign(baseClaims(), SigningMethodES256, privJWK.Key)
	if _, err := Parse(signed, func(*Token) (any, error) { return pubJWK.Key, nil },
		WithValidMethods([]string{"ES256"}), WithClock(fixedClock{refTime})); err != nil {
		t.Fatalf("ec jwk verify: %v", err)
	}
	// Public() strips the private component.
	if privJWK.Public().IsPrivate() {
		t.Fatal("Public() should not be private")
	}
}

func TestJWKOKPRoundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	seed := priv.Seed()
	privJWK, err := ParseJWK([]byte(fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","kid":"o1","x":%q,"d":%q}`,
		b64u(pub), b64u(seed))))
	if err != nil {
		t.Fatalf("parse okp jwk: %v", err)
	}
	if !privJWK.IsPrivate() {
		t.Fatal("okp should be private")
	}
	pubJWK, err := ParseJWK([]byte(fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","kid":"o1","x":%q}`, b64u(pub))))
	if err != nil {
		t.Fatalf("parse okp pub jwk: %v", err)
	}
	signed, _ := Sign(baseClaims(), SigningMethodEdDSA, privJWK.Key)
	if _, err := Parse(signed, func(*Token) (any, error) { return pubJWK.Key, nil },
		WithValidMethods([]string{"EdDSA"}), WithClock(fixedClock{refTime})); err != nil {
		t.Fatalf("okp jwk verify: %v", err)
	}
}

func TestJWKOct(t *testing.T) {
	secret := []byte("symmetric-secret-key")
	jwk, err := ParseJWK([]byte(fmt.Sprintf(`{"kty":"oct","kid":"s1","k":%q}`, b64u(secret))))
	if err != nil {
		t.Fatalf("parse oct jwk: %v", err)
	}
	got, ok := jwk.Key.([]byte)
	if !ok || string(got) != string(secret) {
		t.Fatalf("oct jwk key mismatch: %v", got)
	}
	if jwk.IsPrivate() {
		t.Fatal("oct is symmetric, IsPrivate should be false")
	}
	tp, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil || len(tp) != 32 {
		t.Fatalf("oct thumbprint: %v %d", err, len(tp))
	}
}

func TestJWKErrors(t *testing.T) {
	for _, bad := range []string{
		`{}`,                         // missing kty
		`{"kty":"XYZ"}`,              // unsupported kty
		`{"kty":"EC","crv":"P-999"}`, // bad curve
		`not json`,
		`{"kty":"OKP","crv":"X25519","x":"AA"}`, // unsupported OKP curve
	} {
		if _, err := ParseJWK([]byte(bad)); err == nil {
			t.Fatalf("expected error for %q", bad)
		}
	}
	// EC point not on curve.
	if _, err := ParseJWK([]byte(`{"kty":"EC","crv":"P-256","x":"AQAB","y":"AQAB"}`)); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("expected ErrInvalidKey for off-curve point, got %v", err)
	}
}

func TestJWKSetLookupAndKeyfunc(t *testing.T) {
	priv1, _ := rsa.GenerateKey(rand.Reader, 2048)
	priv2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	setJSON := fmt.Sprintf(`{"keys":[%s,%s]}`,
		fmt.Sprintf(`{"kty":"RSA","kid":"rsa-1","alg":"RS256","n":%q,"e":%q}`,
			b64u(priv1.N.Bytes()), b64u(big.NewInt(int64(priv1.E)).Bytes())),
		ecJWK(t, priv2, "P-256", "ec-1", false))
	set, err := ParseJWKSet([]byte(setJSON))
	if err != nil {
		t.Fatalf("parse set: %v", err)
	}
	if len(set.LookupKeyID("rsa-1")) != 1 || len(set.LookupKeyID("missing")) != 0 {
		t.Fatal("LookupKeyID")
	}
	if _, err := set.Key("missing"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Key(missing): %v", err)
	}

	// Sign with RSA key, verify through the set's keyfunc by kid.
	tok := NewWithClaims(SigningMethodRS256, baseClaims()).SetKID("rsa-1")
	signed, _ := tok.SignedString(priv1)
	if _, err := Parse(signed, set.Keyfunc(),
		WithValidMethods([]string{"RS256"}), WithClock(fixedClock{refTime})); err != nil {
		t.Fatalf("set keyfunc verify: %v", err)
	}

	// Same token but claiming a different alg than the JWK => rejected.
	badHeader := EncodeSegment([]byte(`{"alg":"RS512","typ":"JWT","kid":"rsa-1"}`))
	_, err = set.Keyfunc()(&Token{Header: map[string]any{"alg": "RS512", "kid": "rsa-1"}})
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("expected alg mismatch rejection, got %v", err)
	}
	_ = badHeader
}

func TestJWKRSAPrivateRoundTrip(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwkJSON := fmt.Sprintf(`{"kty":"RSA","kid":"rp","n":%q,"e":%q,"d":%q,"p":%q,"q":%q}`,
		b64u(priv.N.Bytes()), b64u(big.NewInt(int64(priv.E)).Bytes()),
		b64u(priv.D.Bytes()), b64u(priv.Primes[0].Bytes()), b64u(priv.Primes[1].Bytes()))
	jwk, err := ParseJWK([]byte(jwkJSON))
	if err != nil {
		t.Fatalf("parse rsa private jwk: %v", err)
	}
	if !jwk.IsPrivate() {
		t.Fatal("expected private RSA jwk")
	}
	signed, err := Sign(baseClaims(), SigningMethodRS256, jwk.Key)
	if err != nil {
		t.Fatalf("sign with jwk private: %v", err)
	}
	// Public() yields a verify key.
	pub := jwk.Public()
	if pub.IsPrivate() {
		t.Fatal("Public() still private")
	}
	if _, err := Parse(signed, func(*Token) (any, error) { return pub.Key, nil },
		WithValidMethods([]string{"RS256"}), WithClock(fixedClock{refTime})); err != nil {
		t.Fatalf("verify with rsa public jwk: %v", err)
	}
}

func TestJWKSetKeySingle(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	setJSON := fmt.Sprintf(`{"keys":[{"kty":"RSA","n":%q,"e":%q}]}`,
		b64u(priv.N.Bytes()), b64u(big.NewInt(int64(priv.E)).Bytes()))
	set, err := ParseJWKSet([]byte(setJSON))
	if err != nil {
		t.Fatal(err)
	}
	// Empty kid with exactly one key returns that key.
	if _, err := set.Key(""); err != nil {
		t.Fatalf("single-key lookup: %v", err)
	}
}

func TestParseJWKSetError(t *testing.T) {
	if _, err := ParseJWKSet([]byte(`{"keys":[{"kty":"EC","crv":"bad"}]}`)); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("expected ErrInvalidKey, got %v", err)
	}
	if _, err := ParseJWKSet([]byte(`not json`)); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("expected ErrInvalidKey, got %v", err)
	}
}

func TestThumbprintErrors(t *testing.T) {
	// A JWK with an unsupported kty cannot be thumbprinted... but parse rejects
	// unsupported kty first, so test the individual member-missing paths by
	// constructing JWK values directly.
	jwk := &JSONWebKey{Kty: "RSA"} // missing n/e
	if _, err := jwk.Thumbprint(crypto.SHA256); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("rsa missing members: %v", err)
	}
	ec := &JSONWebKey{Kty: "EC", Crv: "P-256"} // missing x/y
	if _, err := ec.Thumbprint(crypto.SHA256); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("ec missing members: %v", err)
	}
	okp := &JSONWebKey{Kty: "OKP", Crv: "Ed25519"} // missing x
	if _, err := okp.Thumbprint(crypto.SHA256); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("okp missing members: %v", err)
	}
	unk := &JSONWebKey{Kty: "weird"}
	if _, err := unk.Thumbprint(crypto.SHA256); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("unknown kty thumbprint: %v", err)
	}
}

// ---- JWKS cache -------------------------------------------------------------

type fakeDoer struct {
	body   string
	status int
	calls  int
	err    error
}

func (f *fakeDoer) Do(req *http.Request) (*http.Response, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	status := f.status
	if status == 0 {
		status = 200
	}
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(f.body)),
		Header:     make(http.Header),
	}, nil
}

func TestJWKSCache(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	body := fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":"k1","alg":"RS256","n":%q,"e":%q}]}`,
		b64u(priv.N.Bytes()), b64u(big.NewInt(int64(priv.E)).Bytes()))
	doer := &fakeDoer{body: body}

	now := refTime
	cache := NewJWKSCache("https://issuer.example/jwks.json",
		WithHTTPClient(doer),
		WithRefreshInterval(time.Hour),
		withClock(func() time.Time { return now }))

	tok := NewWithClaims(SigningMethodRS256, baseClaims()).SetKID("k1")
	signed, _ := tok.SignedString(priv)

	kf := cache.KeyfuncCtx(context.Background())
	if _, err := Parse(signed, kf, WithValidMethods([]string{"RS256"}), WithClock(fixedClock{refTime})); err != nil {
		t.Fatalf("cache verify: %v", err)
	}
	if doer.calls != 1 {
		t.Fatalf("expected 1 fetch, got %d", doer.calls)
	}
	// Second use within TTL: no new fetch.
	if _, err := Parse(signed, kf, WithValidMethods([]string{"RS256"}), WithClock(fixedClock{refTime})); err != nil {
		t.Fatalf("cache verify 2: %v", err)
	}
	if doer.calls != 1 {
		t.Fatalf("expected still 1 fetch, got %d", doer.calls)
	}
	// Advance beyond TTL: triggers a refresh.
	now = refTime.Add(2 * time.Hour)
	if _, err := cache.KeySet(context.Background()); err != nil {
		t.Fatalf("KeySet refresh: %v", err)
	}
	if doer.calls != 2 {
		t.Fatalf("expected 2 fetches after TTL, got %d", doer.calls)
	}
}

func TestJWKSCacheKidMissRefresh(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	body := fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":"k1","alg":"RS256","n":%q,"e":%q}]}`,
		b64u(priv.N.Bytes()), b64u(big.NewInt(int64(priv.E)).Bytes()))
	doer := &fakeDoer{body: body}
	now := refTime
	cache := NewJWKSCache("https://x/jwks", WithHTTPClient(doer),
		WithMinRefreshInterval(time.Minute), withClock(func() time.Time { return now }))

	// Warm the cache.
	if err := cache.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	kf := cache.Keyfunc()
	// Unknown kid triggers at most one refresh within the window, then fails.
	_, err := kf(&Token{Header: map[string]any{"alg": "RS256", "kid": "unknown"}})
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound, got %v", err)
	}
	callsAfterMiss := doer.calls
	// Immediate retry within minRefresh must NOT fetch again.
	_, _ = kf(&Token{Header: map[string]any{"alg": "RS256", "kid": "unknown"}})
	if doer.calls != callsAfterMiss {
		t.Fatalf("rate limit failed: %d vs %d", doer.calls, callsAfterMiss)
	}
}

func TestJWKSCacheFetchError(t *testing.T) {
	doer := &fakeDoer{status: 500, body: "boom"}
	cache := NewJWKSCache("https://x/jwks", WithHTTPClient(doer),
		withClock(func() time.Time { return refTime }))
	if _, err := cache.KeySet(context.Background()); !errors.Is(err, ErrJWKSFetch) {
		t.Fatalf("expected ErrJWKSFetch, got %v", err)
	}
}

// ---- Detached / unencoded payload (RFC 7797) --------------------------------

func TestDetachedPayloadRoundTrip(t *testing.T) {
	secret := []byte("detached-secret")
	payload := []byte("this is the detached, unencoded payload $ with . dots")
	jws, err := SignDetached(payload, SigningMethodHS256, secret, map[string]any{"kid": "d1"})
	if err != nil {
		t.Fatalf("sign detached: %v", err)
	}
	// Serialization is header..signature (empty middle segment).
	parts := strings.Split(jws, ".")
	if len(parts) != 3 || parts[1] != "" {
		t.Fatalf("unexpected detached form: %q", jws)
	}
	tok, err := VerifyDetached(jws, payload, func(*Token) (any, error) { return secret, nil },
		WithValidMethods([]string{"HS256"}))
	if err != nil {
		t.Fatalf("verify detached: %v", err)
	}
	if !tok.Valid || tok.Header["kid"] != "d1" {
		t.Fatalf("detached token header lost: %+v", tok.Header)
	}
	// Wrong payload fails.
	if _, err := VerifyDetached(jws, []byte("tampered"), func(*Token) (any, error) { return secret, nil }); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("expected ErrSignatureInvalid for wrong payload, got %v", err)
	}
	// Non-empty payload segment is rejected.
	bad := parts[0] + "." + EncodeSegment(payload) + "." + parts[2]
	if _, err := VerifyDetached(bad, payload, func(*Token) (any, error) { return secret, nil }); !errors.Is(err, ErrTokenMalformed) {
		t.Fatalf("expected ErrTokenMalformed, got %v", err)
	}
}

func TestDetachedEdDSA(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	payload := []byte("edcs-payload")
	jws, err := SignDetached(payload, SigningMethodEdDSA, priv, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyDetached(jws, payload, func(*Token) (any, error) { return pub, nil },
		WithValidMethods([]string{"EdDSA"})); err != nil {
		t.Fatalf("detached eddsa verify: %v", err)
	}
}

// ---- ParseUnverified --------------------------------------------------------

func TestParseUnverified(t *testing.T) {
	secret := []byte("k")
	tok := NewWithClaims(SigningMethodHS256, MapClaims{"iss": "who", "kid-hint": "abc"}).SetKID("kid-9")
	signed, _ := tok.SignedString(secret)

	got, parts, err := ParseUnverified(signed, MapClaims{})
	if err != nil {
		t.Fatalf("parse unverified: %v", err)
	}
	if got.Valid {
		t.Fatal("unverified token must not be marked valid")
	}
	if got.Header["kid"] != "kid-9" {
		t.Fatalf("header not decoded: %v", got.Header)
	}
	mc := got.Claims.(MapClaims)
	if mc.GetIssuer() != "who" {
		t.Fatalf("claims not decoded: %v", mc)
	}
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts, got %d", len(parts))
	}
	// Even with the WRONG key we can inspect via unverified.
	if _, _, err := NewParser().ParseUnverified("bad.token", MapClaims{}); !errors.Is(err, ErrTokenMalformed) {
		t.Fatalf("expected malformed, got %v", err)
	}
}

// ---- New parser options -----------------------------------------------------

func TestWithMaxTokenAge(t *testing.T) {
	secret := []byte("k")
	// iat two hours before the verification time.
	claims := RegisteredClaims{IssuedAt: NewNumericDate(refTime.Add(-2 * time.Hour))}
	signed, _ := Sign(claims, SigningMethodHS256, secret)
	_, err := Parse(signed, func(*Token) (any, error) { return secret, nil },
		WithClock(fixedClock{refTime}), WithMaxTokenAge(time.Hour))
	if !errors.Is(err, ErrTokenTooOld) {
		t.Fatalf("expected ErrTokenTooOld, got %v", err)
	}
	// Within the age bound it passes.
	if _, err := Parse(signed, func(*Token) (any, error) { return secret, nil },
		WithClock(fixedClock{refTime}), WithMaxTokenAge(3*time.Hour)); err != nil {
		t.Fatalf("within age: %v", err)
	}
	// Missing iat with a max-age requirement is rejected.
	noIat, _ := Sign(RegisteredClaims{Issuer: "x"}, SigningMethodHS256, secret)
	if _, err := Parse(noIat, func(*Token) (any, error) { return secret, nil },
		WithClock(fixedClock{refTime}), WithMaxTokenAge(time.Hour)); !errors.Is(err, ErrTokenRequiredClaimMissing) {
		t.Fatalf("expected required-claim error, got %v", err)
	}
}

func TestWithRequiredClaims(t *testing.T) {
	secret := []byte("k")
	signed, _ := Sign(MapClaims{"iss": "x", "custom": "yes"}, SigningMethodHS256, secret)
	if _, err := Parse(signed, func(*Token) (any, error) { return secret, nil },
		WithClock(fixedClock{refTime}), WithRequiredClaims("iss", "custom")); err != nil {
		t.Fatalf("required present: %v", err)
	}
	if _, err := Parse(signed, func(*Token) (any, error) { return secret, nil },
		WithClock(fixedClock{refTime}), WithRequiredClaims("missing")); !errors.Is(err, ErrTokenRequiredClaimMissing) {
		t.Fatalf("expected required-claim missing, got %v", err)
	}
}

func TestWithValidTypes(t *testing.T) {
	secret := []byte("k")
	// Default typ is "JWT".
	signed, _ := Sign(RegisteredClaims{Issuer: "x"}, SigningMethodHS256, secret)
	if _, err := Parse(signed, func(*Token) (any, error) { return secret, nil },
		WithClock(fixedClock{refTime}), WithValidTypes("jwt")); err != nil { // case-insensitive
		t.Fatalf("valid typ: %v", err)
	}
	if _, err := Parse(signed, func(*Token) (any, error) { return secret, nil },
		WithClock(fixedClock{refTime}), WithValidTypes("at+jwt")); !errors.Is(err, ErrInvalidTyp) {
		t.Fatalf("expected ErrInvalidTyp, got %v", err)
	}
}

func TestCritHeaderRejection(t *testing.T) {
	secret := []byte("k")
	// Craft a token with an unknown critical header.
	header := EncodeSegment([]byte(`{"alg":"HS256","typ":"JWT","crit":["exp"],"exp":1}`))
	payload := EncodeSegment([]byte(`{"iss":"x"}`))
	sig, _ := SigningMethodHS256.Sign(header+"."+payload, secret)
	token := header + "." + payload + "." + EncodeSegment(sig)
	if _, err := Parse(token, func(*Token) (any, error) { return secret, nil },
		WithClock(fixedClock{refTime})); !errors.Is(err, ErrInvalidCrit) {
		t.Fatalf("expected ErrInvalidCrit for unknown crit, got %v", err)
	}
	// A known critical header (registered via option) is accepted.
	header2 := EncodeSegment([]byte(`{"alg":"HS256","typ":"JWT","crit":["myext"],"myext":true}`))
	sig2, _ := SigningMethodHS256.Sign(header2+"."+payload, secret)
	token2 := header2 + "." + payload + "." + EncodeSegment(sig2)
	if _, err := Parse(token2, func(*Token) (any, error) { return secret, nil },
		WithClock(fixedClock{refTime}), WithKnownCriticalHeaders("myext")); err != nil {
		t.Fatalf("known crit should pass: %v", err)
	}
	// crit listing an absent header is rejected.
	header3 := EncodeSegment([]byte(`{"alg":"HS256","typ":"JWT","crit":["b64"]}`))
	sig3, _ := SigningMethodHS256.Sign(header3+"."+payload, secret)
	token3 := header3 + "." + payload + "." + EncodeSegment(sig3)
	if _, err := Parse(token3, func(*Token) (any, error) { return secret, nil },
		WithClock(fixedClock{refTime})); !errors.Is(err, ErrInvalidCrit) {
		t.Fatalf("expected ErrInvalidCrit for absent crit member, got %v", err)
	}
}

// ---- MapClaims helpers & Token.String --------------------------------------

func TestMapClaimsExtraHelpers(t *testing.T) {
	mc := MapClaims{"jti": "id-1", "nonce": "n-1", "azp": "client-1", "role": "admin"}
	if mc.GetID() != "id-1" || mc.GetNonce() != "n-1" || mc.GetAuthorizedParty() != "client-1" {
		t.Fatalf("map claim helpers: %+v", mc)
	}
	if mc.GetString("role") != "admin" || mc.GetString("absent") != "" {
		t.Fatal("GetString")
	}
}

func TestTokenStringRoundTrip(t *testing.T) {
	secret := []byte("k")
	tok := NewWithClaims(SigningMethodHS256, baseClaims())
	signed, _ := tok.SignedString(secret)
	if tok.String() != signed {
		t.Fatal("SignedString should populate Raw / String")
	}
	parsed, err := Parse(signed, func(*Token) (any, error) { return secret, nil },
		WithClock(fixedClock{refTime}))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.String() != signed {
		t.Fatalf("parse/serialize round-trip mismatch:\n%q\n%q", parsed.String(), signed)
	}
}

// ensure the JWK marshaling path is exercised.
func TestJWKMarshal(t *testing.T) {
	jwk, _ := ParseJWK([]byte(`{"kty":"oct","kid":"m1","k":"AAAA"}`))
	data, err := json.Marshal(jwk)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"kid":"m1"`) {
		t.Fatalf("marshal lost kid: %s", data)
	}
}
