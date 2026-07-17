package jwt

import (
	"crypto"
	"crypto/hmac"
	_ "crypto/sha256" // link SHA-256 for crypto.Hash.New
	_ "crypto/sha512" // link SHA-384 and SHA-512
	"fmt"
)

// SigningMethodHMAC implements the HMAC-SHA family (HS256, HS384, HS512).
// The signing key must be a []byte secret.
type SigningMethodHMAC struct {
	Name string
	Hash crypto.Hash
}

// Predefined HMAC signing methods.
var (
	SigningMethodHS256 = &SigningMethodHMAC{Name: "HS256", Hash: crypto.SHA256}
	SigningMethodHS384 = &SigningMethodHMAC{Name: "HS384", Hash: crypto.SHA384}
	SigningMethodHS512 = &SigningMethodHMAC{Name: "HS512", Hash: crypto.SHA512}
)

func init() {
	RegisterSigningMethod(SigningMethodHS256.Name, func() SigningMethod { return SigningMethodHS256 })
	RegisterSigningMethod(SigningMethodHS384.Name, func() SigningMethod { return SigningMethodHS384 })
	RegisterSigningMethod(SigningMethodHS512.Name, func() SigningMethod { return SigningMethodHS512 })
}

// Alg returns the JWS alg identifier.
func (m *SigningMethodHMAC) Alg() string { return m.Name }

// Sign computes HMAC(key, signingString). key must be a []byte.
func (m *SigningMethodHMAC) Sign(signingString string, key any) ([]byte, error) {
	secret, ok := key.([]byte)
	if !ok {
		return nil, fmt.Errorf("%w: HMAC requires []byte, got %T", ErrInvalidKeyType, key)
	}
	if !m.Hash.Available() {
		return nil, ErrHashUnavailable
	}
	h := hmac.New(m.Hash.New, secret)
	h.Write([]byte(signingString))
	return h.Sum(nil), nil
}

// Verify recomputes the MAC and compares it in constant time.
func (m *SigningMethodHMAC) Verify(signingString string, sig []byte, key any) error {
	secret, ok := key.([]byte)
	if !ok {
		return fmt.Errorf("%w: HMAC requires []byte, got %T", ErrInvalidKeyType, key)
	}
	if !m.Hash.Available() {
		return ErrHashUnavailable
	}
	h := hmac.New(m.Hash.New, secret)
	h.Write([]byte(signingString))
	if !hmac.Equal(sig, h.Sum(nil)) {
		return ErrSignatureInvalid
	}
	return nil
}
