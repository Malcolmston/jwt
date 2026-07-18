package jwt

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestEncodeRSAKeysRoundTrip(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	privPEM := EncodeRSAPrivateKeyToPEM(priv)
	got, err := ParseRSAPrivateKeyFromPEM(privPEM)
	if err != nil {
		t.Fatalf("parse private: %v", err)
	}
	if got.D.Cmp(priv.D) != 0 || got.N.Cmp(priv.N) != 0 {
		t.Fatal("RSA private key did not round-trip")
	}
	pubPEM, err := EncodeRSAPublicKeyToPEM(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	gotPub, err := ParseRSAPublicKeyFromPEM(pubPEM)
	if err != nil {
		t.Fatalf("parse public: %v", err)
	}
	if gotPub.N.Cmp(priv.N) != 0 || gotPub.E != priv.E {
		t.Fatal("RSA public key did not round-trip")
	}
}

func TestEncodeECKeysRoundTrip(t *testing.T) {
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		priv, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		privPEM, err := EncodeECPrivateKeyToPEM(priv)
		if err != nil {
			t.Fatal(err)
		}
		got, err := ParseECPrivateKeyFromPEM(privPEM)
		if err != nil {
			t.Fatalf("parse EC private: %v", err)
		}
		if got.D.Cmp(priv.D) != 0 {
			t.Fatal("EC private key did not round-trip")
		}
		pubPEM, err := EncodeECPublicKeyToPEM(&priv.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		gotPub, err := ParseECPublicKeyFromPEM(pubPEM)
		if err != nil {
			t.Fatalf("parse EC public: %v", err)
		}
		if gotPub.X.Cmp(priv.X) != 0 || gotPub.Y.Cmp(priv.Y) != 0 {
			t.Fatal("EC public key did not round-trip")
		}
	}
}

func TestEncodeEdKeysRoundTrip(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	privPEM, err := EncodeEdPrivateKeyToPEM(priv)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseEdPrivateKeyFromPEM(privPEM)
	if err != nil {
		t.Fatalf("parse Ed private: %v", err)
	}
	if !got.Equal(priv) {
		t.Fatal("Ed25519 private key did not round-trip")
	}
	pub := priv.Public().(ed25519.PublicKey)
	pubPEM, err := EncodeEdPublicKeyToPEM(pub)
	if err != nil {
		t.Fatal(err)
	}
	gotPub, err := ParseEdPublicKeyFromPEM(pubPEM)
	if err != nil {
		t.Fatalf("parse Ed public: %v", err)
	}
	if !gotPub.Equal(pub) {
		t.Fatal("Ed25519 public key did not round-trip")
	}
}

func TestEncodeGenericKeysToPEM(t *testing.T) {
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, edk, _ := ed25519.GenerateKey(rand.Reader)

	for name, key := range map[string]any{"rsa": rk, "ec": ek, "ed": edk} {
		privPEM, err := EncodePrivateKeyToPEM(key)
		if err != nil {
			t.Fatalf("%s private: %v", name, err)
		}
		if len(privPEM) == 0 {
			t.Fatalf("%s: empty private PEM", name)
		}
	}
	for name, pub := range map[string]any{"rsa": &rk.PublicKey, "ec": &ek.PublicKey, "ed": edk.Public()} {
		pubPEM, err := EncodePublicKeyToPEM(pub)
		if err != nil {
			t.Fatalf("%s public: %v", name, err)
		}
		if len(pubPEM) == 0 {
			t.Fatalf("%s: empty public PEM", name)
		}
	}
}

func TestEncodeUnsupportedKeyTypes(t *testing.T) {
	if _, err := EncodePrivateKeyToPEM("not a key"); err == nil {
		t.Fatal("expected error for unsupported private key type")
	}
	if _, err := EncodePublicKeyToPEM(42); err == nil {
		t.Fatal("expected error for unsupported public key type")
	}
}

func BenchmarkEncodeRSAPrivateKeyToPEM(b *testing.B) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = EncodeRSAPrivateKeyToPEM(priv)
	}
}
