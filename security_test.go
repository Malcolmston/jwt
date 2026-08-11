package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
)

// rawHMACSHA256 computes HMAC-SHA256 directly, bypassing SigningMethodHMAC.
func rawHMACSHA256(secret []byte, signingString string) []byte {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(signingString))
	return h.Sum(nil)
}

// rsaPublicPEM returns a freshly generated RSA key together with the PKIX PEM
// encoding of its public half — the material an attacker has by definition.
func rsaPublicPEM(t *testing.T) (*rsa.PrivateKey, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshaling public key: %v", err)
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// TestAlgConfusionPublicKeyAsHMACSecret is the GHSA-75rm-5v4f-887v repro: an
// HS256 token MACed with the bytes of the verifier's RSA public key must not be
// accepted, and this package must refuse to mint one in the first place.
func TestAlgConfusionPublicKeyAsHMACSecret(t *testing.T) {
	_, pub := rsaPublicPEM(t)

	tok := NewWithClaims(SigningMethodHS256, MapClaims{"sub": "attacker"})
	if _, err := tok.SignedString(pub); !errors.Is(err, ErrAsymmetricKeyForHMAC) {
		t.Fatalf("signing with a public key PEM: err = %v, want ErrAsymmetricKeyForHMAC", err)
	}

	// Even when the forgery is minted out of band (as an attacker would), it must
	// be rejected on the verification path with no allowlist configured.
	forged := forgeHS256(t, pub, `{"sub":"attacker"}`)
	parsed, err := Parse(forged, func(*Token) (any, error) { return pub, nil })
	if !errors.Is(err, ErrAsymmetricKeyForHMAC) {
		t.Fatalf("parsing forgery: err = %v, want ErrAsymmetricKeyForHMAC", err)
	}
	if parsed != nil && parsed.Valid {
		t.Fatal("forged token was reported valid")
	}
}

// TestHMACRejectsECPublicKeyPEM covers the EC variant of the same confusion.
func TestHMACRejectsECPublicKeyPEM(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating EC key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshaling EC public key: %v", err)
	}
	pub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})

	forged := forgeHS256(t, pub, `{"sub":"attacker"}`)
	if _, err := Parse(forged, func(*Token) (any, error) { return pub, nil }); !errors.Is(err, ErrAsymmetricKeyForHMAC) {
		t.Fatalf("EC public key as HMAC secret: err = %v, want ErrAsymmetricKeyForHMAC", err)
	}
	if _, err := SigningMethodHS256.Sign("x.y", pub); !errors.Is(err, ErrAsymmetricKeyForHMAC) {
		t.Fatalf("signing with EC public key PEM: err = %v, want ErrAsymmetricKeyForHMAC", err)
	}
}

// TestHMACRejectsRSAPrivateKeyPEM guards the mirror-image mistake of handing a
// private key PEM to an HS* method.
func TestHMACRejectsRSAPrivateKeyPEM(t *testing.T) {
	key, _ := rsaPublicPEM(t)
	priv := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	if _, err := SigningMethodHS256.Sign("x.y", priv); !errors.Is(err, ErrAsymmetricKeyForHMAC) {
		t.Fatalf("signing with RSA private key PEM: err = %v, want ErrAsymmetricKeyForHMAC", err)
	}
	if err := SigningMethodHS256.Verify("x.y", []byte("sig"), priv); !errors.Is(err, ErrAsymmetricKeyForHMAC) {
		t.Fatalf("verifying with RSA private key PEM: err = %v, want ErrAsymmetricKeyForHMAC", err)
	}
}

// TestHMACRejectsTypedAsymmetricKeys covers typed key values, which carry no
// encoding for the byte-level guard to inspect.
func TestHMACRejectsTypedAsymmetricKeys(t *testing.T) {
	rsaKey, _ := rsaPublicPEM(t)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating EC key: %v", err)
	}
	keys := []any{&rsaKey.PublicKey, rsaKey, &ecKey.PublicKey, ecKey}
	for _, k := range keys {
		if _, err := SigningMethodHS256.Sign("x.y", k); !errors.Is(err, ErrAsymmetricKeyForHMAC) {
			t.Errorf("Sign with %T: err = %v, want ErrAsymmetricKeyForHMAC", k, err)
		}
		if err := SigningMethodHS256.Verify("x.y", nil, k); !errors.Is(err, ErrAsymmetricKeyForHMAC) {
			t.Errorf("Verify with %T: err = %v, want ErrAsymmetricKeyForHMAC", k, err)
		}
	}
	// ErrAsymmetricKeyForHMAC wraps ErrInvalidKeyType, so callers that already
	// test for the broader category keep working.
	if _, err := SigningMethodHS256.Sign("x.y", &rsaKey.PublicKey); !errors.Is(err, ErrInvalidKeyType) {
		t.Errorf("err = %v, want it to also match ErrInvalidKeyType", err)
	}
}

// TestEmptyAllowlistRejectsEverything is the GHSA-2vc9-3gjf-2276 repro: an
// empty, non-nil allowlist permits nothing rather than restricting nothing.
func TestEmptyAllowlistRejectsEverything(t *testing.T) {
	secret := []byte("a-real-symmetric-secret")
	signed, err := NewWithClaims(SigningMethodHS256, MapClaims{"sub": "alice"}).SignedString(secret)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	kf := func(*Token) (any, error) { return secret, nil }

	parsed, err := Parse(signed, kf, WithValidMethods([]string{}))
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("empty allowlist: err = %v, want ErrSignatureInvalid", err)
	}
	if parsed != nil && parsed.Valid {
		t.Fatal("token accepted under an empty allowlist")
	}

	// A nil allowlist means "not configured" and must leave the token acceptable,
	// preserving the behavior of callers that pass no allowlist at all.
	if _, err := Parse(signed, kf, WithValidMethods(nil)); err != nil {
		t.Fatalf("nil allowlist: err = %v, want nil", err)
	}

	// The distinction also holds for detached JWS verification.
	detached, err := SignDetached([]byte("payload"), SigningMethodHS256, secret, nil)
	if err != nil {
		t.Fatalf("SignDetached: %v", err)
	}
	if _, err := VerifyDetached(detached, []byte("payload"), kf, WithValidMethods([]string{})); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("detached empty allowlist: err = %v, want ErrSignatureInvalid", err)
	}
	if _, err := VerifyDetached(detached, []byte("payload"), kf, WithValidMethods(nil)); err != nil {
		t.Fatalf("detached nil allowlist: err = %v, want nil", err)
	}
}

// TestAlgNoneStillRejected pins the unsecured-token behavior alongside the two
// advisories: alg "none" is refused unless explicitly opted into.
func TestAlgNoneStillRejected(t *testing.T) {
	unsecured, err := NewWithClaims(SigningMethodNoneAlg, MapClaims{"sub": "attacker"}).
		SignedString(UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("building unsecured token: %v", err)
	}
	if _, err := Parse(unsecured, func(*Token) (any, error) { return []byte("secret"), nil }); !errors.Is(err, ErrNoneAlgDisallowed) {
		t.Fatalf("alg none: err = %v, want ErrNoneAlgDisallowed", err)
	}
	// An empty allowlist rejects it too, before the none-specific check.
	if _, err := Parse(unsecured, func(*Token) (any, error) { return UnsafeAllowNoneSignatureType, nil },
		WithAllowNone(), WithValidMethods([]string{})); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("alg none under empty allowlist: err = %v, want ErrSignatureInvalid", err)
	}
}

// TestLegitimateHS256FlowStillWorks is the control: a genuine symmetric secret
// must keep round-tripping, including secrets long enough to be mistaken for
// key material.
func TestLegitimateHS256FlowStillWorks(t *testing.T) {
	for _, secret := range [][]byte{
		[]byte("hunter2"),
		make([]byte, 64), // all-zero bytes: not PEM, not DER
	} {
		signed, err := NewWithClaims(SigningMethodHS256, MapClaims{"sub": "alice"}).SignedString(secret)
		if err != nil {
			t.Fatalf("signing with a symmetric secret: %v", err)
		}
		tok, err := Parse(signed, func(*Token) (any, error) { return secret, nil },
			WithValidMethods([]string{"HS256"}))
		if err != nil {
			t.Fatalf("parsing: %v", err)
		}
		if !tok.Valid {
			t.Fatal("legitimate HS256 token was not valid")
		}
		if sub, _ := tok.Claims.(MapClaims)["sub"].(string); sub != "alice" {
			t.Fatalf("sub = %q, want alice", sub)
		}
	}
	// Random secrets of key-like length must not trip the guard either.
	random := make([]byte, 294)
	if _, err := rand.Read(random); err != nil {
		t.Fatalf("reading randomness: %v", err)
	}
	if _, err := SigningMethodHS256.Sign("x.y", random); err != nil {
		t.Fatalf("random 294-byte secret rejected: %v", err)
	}
}

// forgeHS256 mints an HS256 token keyed with secret without going through this
// package's guarded signing path, standing in for the attacker's own tooling.
func forgeHS256(t *testing.T, secret []byte, claimsJSON string) string {
	t.Helper()
	header := EncodeSegment([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := EncodeSegment([]byte(claimsJSON))
	mac := rawHMACSHA256(secret, header+"."+payload)
	return header + "." + payload + "." + EncodeSegment(mac)
}
