package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"math/big"
)

// SigningMethodECDSA implements ECDSA (ES256, ES384, ES512). Signatures use the
// fixed-width r||s concatenation format defined by RFC 7518, not the ASN.1 DER
// form produced by ecdsa.SignASN1. Signing keys are *ecdsa.PrivateKey and
// verification keys are *ecdsa.PublicKey.
type SigningMethodECDSA struct {
	Name string
	Hash crypto.Hash
	// KeySize is the byte length of each of r and s for this curve.
	KeySize int
}

// Predefined ECDSA signing methods. ES512 uses the P-521 curve, whose field is
// 521 bits, i.e. 66 bytes per coordinate.
var (
	SigningMethodES256 = &SigningMethodECDSA{Name: "ES256", Hash: crypto.SHA256, KeySize: 32}
	SigningMethodES384 = &SigningMethodECDSA{Name: "ES384", Hash: crypto.SHA384, KeySize: 48}
	SigningMethodES512 = &SigningMethodECDSA{Name: "ES512", Hash: crypto.SHA512, KeySize: 66}
)

func init() {
	RegisterSigningMethod(SigningMethodES256.Name, func() SigningMethod { return SigningMethodES256 })
	RegisterSigningMethod(SigningMethodES384.Name, func() SigningMethod { return SigningMethodES384 })
	RegisterSigningMethod(SigningMethodES512.Name, func() SigningMethod { return SigningMethodES512 })
}

// Alg returns the JWS alg identifier.
func (m *SigningMethodECDSA) Alg() string { return m.Name }

// Sign signs signingString with an *ecdsa.PrivateKey and returns the r||s
// fixed-width encoding.
func (m *SigningMethodECDSA) Sign(signingString string, key any) ([]byte, error) {
	priv, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w: ECDSA requires *ecdsa.PrivateKey, got %T", ErrInvalidKeyType, key)
	}
	hashed, err := hashSum(m.Hash, signingString)
	if err != nil {
		return nil, err
	}
	r, s, err := ecdsa.Sign(rand.Reader, priv, hashed)
	if err != nil {
		return nil, err
	}
	// Left-pad r and s to the fixed coordinate size and concatenate.
	sig := make([]byte, 2*m.KeySize)
	r.FillBytes(sig[:m.KeySize])
	s.FillBytes(sig[m.KeySize:])
	return sig, nil
}

// Verify verifies an r||s fixed-width ECDSA signature with an *ecdsa.PublicKey.
func (m *SigningMethodECDSA) Verify(signingString string, sig []byte, key any) error {
	pub, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("%w: ECDSA requires *ecdsa.PublicKey, got %T", ErrInvalidKeyType, key)
	}
	if len(sig) != 2*m.KeySize {
		return fmt.Errorf("%w: expected %d-byte signature, got %d", ErrSignatureInvalid, 2*m.KeySize, len(sig))
	}
	hashed, err := hashSum(m.Hash, signingString)
	if err != nil {
		return err
	}
	r := new(big.Int).SetBytes(sig[:m.KeySize])
	s := new(big.Int).SetBytes(sig[m.KeySize:])
	if !ecdsa.Verify(pub, hashed, r, s) {
		return ErrSignatureInvalid
	}
	return nil
}
