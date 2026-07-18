package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"reflect"
	"strings"
	"testing"
)

// RFC 7638 §3.1 worked example: this RSA public key has the SHA-256 JWK
// thumbprint "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs".
const rfc7638JWK = `{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB"}`

const rfc7638Thumbprint = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"

func TestNewJSONWebKeyRSAThumbprintKAT(t *testing.T) {
	jwk, err := ParseJWK([]byte(rfc7638JWK))
	if err != nil {
		t.Fatal(err)
	}
	pub := jwk.Key.(*rsa.PublicKey)

	built, err := NewJSONWebKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	if built.E != "AQAB" {
		t.Fatalf("E = %q, want AQAB", built.E)
	}
	tp, err := built.Base64Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if tp != rfc7638Thumbprint {
		t.Fatalf("thumbprint = %q, want %q", tp, rfc7638Thumbprint)
	}
}

func TestThumbprintURI(t *testing.T) {
	jwk, _ := ParseJWK([]byte(rfc7638JWK))
	built, _ := NewJSONWebKey(jwk.Key)
	uri, err := built.ThumbprintURI(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	want := "urn:ietf:params:oauth:jwk-thumbprint:sha-256:" + rfc7638Thumbprint
	if uri != want {
		t.Fatalf("uri = %q, want %q", uri, want)
	}
	if _, err := built.ThumbprintURI(crypto.MD5); err == nil {
		t.Fatal("expected error for unregistered hash name")
	}
}

func TestNewJSONWebKeyRoundTrip(t *testing.T) {
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)

	cases := []struct {
		name string
		key  any
		kty  string
	}{
		{"rsa-pub", &rk.PublicKey, "RSA"},
		{"rsa-priv", rk, "RSA"},
		{"ec-pub", &ek.PublicKey, "EC"},
		{"ec-priv", ek, "EC"},
		{"okp-pub", edPub, "OKP"},
		{"okp-priv", edPriv, "OKP"},
		{"oct", []byte("super-secret-value"), "oct"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			jwk, err := NewJSONWebKey(tc.key)
			if err != nil {
				t.Fatal(err)
			}
			if jwk.Kty != tc.kty {
				t.Fatalf("kty = %q, want %q", jwk.Kty, tc.kty)
			}
			data, err := jwk.MarshalJSON()
			if err != nil {
				t.Fatal(err)
			}
			reparsed, err := ParseJWK(data)
			if err != nil {
				t.Fatalf("reparse: %v", err)
			}
			if !sameKey(reparsed.Key, tc.key) {
				t.Fatalf("key did not round-trip through JWK JSON:\n got %#v\nwant %#v", reparsed.Key, tc.key)
			}
		})
	}
}

// sameKey compares two crypto keys by their mathematically defining fields,
// avoiding reflect.DeepEqual on rsa/ecdsa structs whose unexported precomputed
// caches are not part of the key's identity.
func sameKey(a, b any) bool {
	switch ak := a.(type) {
	case *rsa.PublicKey:
		bk, ok := b.(*rsa.PublicKey)
		return ok && ak.N.Cmp(bk.N) == 0 && ak.E == bk.E
	case *rsa.PrivateKey:
		bk, ok := b.(*rsa.PrivateKey)
		return ok && ak.N.Cmp(bk.N) == 0 && ak.E == bk.E && ak.D.Cmp(bk.D) == 0
	case *ecdsa.PublicKey:
		bk, ok := b.(*ecdsa.PublicKey)
		return ok && ak.Curve == bk.Curve && ak.X.Cmp(bk.X) == 0 && ak.Y.Cmp(bk.Y) == 0
	case *ecdsa.PrivateKey:
		bk, ok := b.(*ecdsa.PrivateKey)
		return ok && ak.Curve == bk.Curve && ak.D.Cmp(bk.D) == 0
	case ed25519.PublicKey:
		bk, ok := b.(ed25519.PublicKey)
		return ok && ak.Equal(bk)
	case ed25519.PrivateKey:
		bk, ok := b.(ed25519.PrivateKey)
		return ok && ak.Equal(bk)
	case []byte:
		bk, ok := b.([]byte)
		return ok && reflect.DeepEqual(ak, bk)
	default:
		return false
	}
}

func TestComputeKeyIDDeterministic(t *testing.T) {
	jwk, _ := ParseJWK([]byte(rfc7638JWK))
	pub := jwk.Key.(*rsa.PublicKey)

	kid, err := ComputeKeyID(pub)
	if err != nil {
		t.Fatal(err)
	}
	if kid != rfc7638Thumbprint {
		t.Fatalf("kid = %q, want %q", kid, rfc7638Thumbprint)
	}
	// The private key must yield the same kid as its public part.
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	kPub, _ := ComputeKeyID(&rk.PublicKey)
	kPriv, _ := ComputeKeyID(rk)
	if kPub != kPriv {
		t.Fatalf("private and public kid differ: %q vs %q", kPriv, kPub)
	}
}

func TestJSONWebKeyBuilderChaining(t *testing.T) {
	jwk, _ := NewJSONWebKey([]byte("k"))
	jwk.WithKeyID("kid-1").WithAlgorithm("HS256").WithUse("sig")
	if jwk.Kid != "kid-1" || jwk.Alg != "HS256" || jwk.Use != "sig" {
		t.Fatalf("chained setters did not apply: %+v", jwk)
	}
}

func TestJSONWebKeySetAdd(t *testing.T) {
	a, _ := NewJSONWebKey([]byte("a"))
	b, _ := NewJSONWebKey([]byte("b"))
	set := &JSONWebKeySet{}
	set.Add(*a).Add(*b)
	if len(set.Keys) != 2 {
		t.Fatalf("len = %d, want 2", len(set.Keys))
	}
}

func TestNewJSONWebKeyErrors(t *testing.T) {
	if _, err := NewJSONWebKey("string is not a key"); err == nil {
		t.Fatal("expected error for unsupported key type")
	}
	if _, err := NewJSONWebKey([]byte{}); err == nil {
		t.Fatal("expected error for empty oct key")
	}
}

func TestThumbprintURIString(t *testing.T) {
	// Sanity: the URI must carry the urn prefix and the base64url thumbprint.
	jwk, _ := NewJSONWebKey([]byte("secret"))
	uri, err := jwk.ThumbprintURI(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(uri, "urn:ietf:params:oauth:jwk-thumbprint:sha-256:") {
		t.Fatalf("bad URI prefix: %q", uri)
	}
}

func BenchmarkComputeKeyID(b *testing.B) {
	jwk, _ := ParseJWK([]byte(rfc7638JWK))
	pub := jwk.Key.(*rsa.PublicKey)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ComputeKeyID(pub)
	}
}
