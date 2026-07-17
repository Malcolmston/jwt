package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

// SigningMethodRSAPSS implements RSASSA-PSS (PS256, PS384, PS512).
// Signing keys are *rsa.PrivateKey and verification keys are *rsa.PublicKey.
type SigningMethodRSAPSS struct {
	Name    string
	Hash    crypto.Hash
	Options *rsa.PSSOptions
}

// Predefined RSA-PSS signing methods. Per RFC 7518 the salt length equals the
// hash output length.
var (
	SigningMethodPS256 = &SigningMethodRSAPSS{
		Name:    "PS256",
		Hash:    crypto.SHA256,
		Options: &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256},
	}
	SigningMethodPS384 = &SigningMethodRSAPSS{
		Name:    "PS384",
		Hash:    crypto.SHA384,
		Options: &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA384},
	}
	SigningMethodPS512 = &SigningMethodRSAPSS{
		Name:    "PS512",
		Hash:    crypto.SHA512,
		Options: &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA512},
	}
)

func init() {
	RegisterSigningMethod(SigningMethodPS256.Name, func() SigningMethod { return SigningMethodPS256 })
	RegisterSigningMethod(SigningMethodPS384.Name, func() SigningMethod { return SigningMethodPS384 })
	RegisterSigningMethod(SigningMethodPS512.Name, func() SigningMethod { return SigningMethodPS512 })
}

// Alg returns the JWS alg identifier.
func (m *SigningMethodRSAPSS) Alg() string { return m.Name }

// Sign signs signingString with an *rsa.PrivateKey using RSA-PSS.
func (m *SigningMethodRSAPSS) Sign(signingString string, key any) ([]byte, error) {
	priv, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w: RSA-PSS requires *rsa.PrivateKey, got %T", ErrInvalidKeyType, key)
	}
	hashed, err := hashSum(m.Hash, signingString)
	if err != nil {
		return nil, err
	}
	return rsa.SignPSS(rand.Reader, priv, m.Hash, hashed, m.Options)
}

// Verify verifies an RSA-PSS signature with an *rsa.PublicKey.
func (m *SigningMethodRSAPSS) Verify(signingString string, sig []byte, key any) error {
	pub, ok := key.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("%w: RSA-PSS requires *rsa.PublicKey, got %T", ErrInvalidKeyType, key)
	}
	hashed, err := hashSum(m.Hash, signingString)
	if err != nil {
		return err
	}
	if err := rsa.VerifyPSS(pub, m.Hash, hashed, sig, m.Options); err != nil {
		return fmt.Errorf("%w: %v", ErrSignatureInvalid, err)
	}
	return nil
}
