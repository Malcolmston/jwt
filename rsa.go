package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

// SigningMethodRSA implements RSASSA-PKCS1-v1_5 (RS256, RS384, RS512).
// Signing keys are *rsa.PrivateKey and verification keys are *rsa.PublicKey.
type SigningMethodRSA struct {
	Name string
	Hash crypto.Hash
}

// Predefined RSA PKCS1v15 signing methods.
var (
	SigningMethodRS256 = &SigningMethodRSA{Name: "RS256", Hash: crypto.SHA256}
	SigningMethodRS384 = &SigningMethodRSA{Name: "RS384", Hash: crypto.SHA384}
	SigningMethodRS512 = &SigningMethodRSA{Name: "RS512", Hash: crypto.SHA512}
)

func init() {
	RegisterSigningMethod(SigningMethodRS256.Name, func() SigningMethod { return SigningMethodRS256 })
	RegisterSigningMethod(SigningMethodRS384.Name, func() SigningMethod { return SigningMethodRS384 })
	RegisterSigningMethod(SigningMethodRS512.Name, func() SigningMethod { return SigningMethodRS512 })
}

// Alg returns the JWS alg identifier.
func (m *SigningMethodRSA) Alg() string { return m.Name }

// Sign signs signingString with an *rsa.PrivateKey using PKCS1v15.
func (m *SigningMethodRSA) Sign(signingString string, key any) ([]byte, error) {
	priv, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w: RSA requires *rsa.PrivateKey, got %T", ErrInvalidKeyType, key)
	}
	if !m.Hash.Available() {
		return nil, ErrHashUnavailable
	}
	hashed, err := hashSum(m.Hash, signingString)
	if err != nil {
		return nil, err
	}
	return rsa.SignPKCS1v15(rand.Reader, priv, m.Hash, hashed)
}

// Verify verifies a PKCS1v15 signature with an *rsa.PublicKey.
func (m *SigningMethodRSA) Verify(signingString string, sig []byte, key any) error {
	pub, ok := key.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("%w: RSA requires *rsa.PublicKey, got %T", ErrInvalidKeyType, key)
	}
	if !m.Hash.Available() {
		return ErrHashUnavailable
	}
	hashed, err := hashSum(m.Hash, signingString)
	if err != nil {
		return err
	}
	if err := rsa.VerifyPKCS1v15(pub, m.Hash, hashed, sig); err != nil {
		return fmt.Errorf("%w: %v", ErrSignatureInvalid, err)
	}
	return nil
}

// hashSum returns the digest of signingString using h.
func hashSum(h crypto.Hash, signingString string) ([]byte, error) {
	if !h.Available() {
		return nil, ErrHashUnavailable
	}
	hasher := h.New()
	hasher.Write([]byte(signingString))
	return hasher.Sum(nil), nil
}
