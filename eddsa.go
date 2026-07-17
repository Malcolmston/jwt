package jwt

import (
	"crypto/ed25519"
	"fmt"
)

// SigningMethodEd25519 implements the EdDSA signing method using the Ed25519
// curve (RFC 8037). The JWS "alg" header value is "EdDSA". Signing keys are
// ed25519.PrivateKey and verification keys are ed25519.PublicKey.
type SigningMethodEd25519 struct{}

// SigningMethodEdDSA is the shared instance of the EdDSA (Ed25519) signing
// method. It is registered under the "EdDSA" alg on import.
var SigningMethodEdDSA = &SigningMethodEd25519{}

func init() {
	RegisterSigningMethod("EdDSA", func() SigningMethod { return SigningMethodEdDSA })
}

// Alg returns "EdDSA", the JWS alg identifier for Ed25519 signatures.
func (m *SigningMethodEd25519) Alg() string { return "EdDSA" }

// Sign signs signingString with an ed25519.PrivateKey and returns the raw
// 64-byte signature. The key must be an ed25519.PrivateKey; any other type
// (including a pointer or an RSA/EC key) is rejected with ErrInvalidKeyType,
// which closes the algorithm-confusion attack surface for this method.
func (m *SigningMethodEd25519) Sign(signingString string, key any) ([]byte, error) {
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w: EdDSA requires ed25519.PrivateKey, got %T", ErrInvalidKeyType, key)
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: ed25519 private key has wrong length %d", ErrInvalidKeyType, len(priv))
	}
	return ed25519.Sign(priv, []byte(signingString)), nil
}

// Verify checks an Ed25519 signature over signingString with an
// ed25519.PublicKey. The key must be an ed25519.PublicKey; any other type is
// rejected with ErrInvalidKeyType.
func (m *SigningMethodEd25519) Verify(signingString string, sig []byte, key any) error {
	pub, ok := key.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("%w: EdDSA requires ed25519.PublicKey, got %T", ErrInvalidKeyType, key)
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: ed25519 public key has wrong length %d", ErrInvalidKeyType, len(pub))
	}
	if !ed25519.Verify(pub, []byte(signingString), sig) {
		return ErrSignatureInvalid
	}
	return nil
}
