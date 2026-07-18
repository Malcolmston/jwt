package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// EncodeRSAPrivateKeyToPEM serializes an RSA private key to PEM using the PKCS#1
// ("RSA PRIVATE KEY") encoding, the inverse of ParseRSAPrivateKeyFromPEM. It
// never fails for a valid key.
func EncodeRSAPrivateKeyToPEM(key *rsa.PrivateKey) []byte {
	der := x509.MarshalPKCS1PrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
}

// EncodeRSAPublicKeyToPEM serializes an RSA public key to PEM using the PKIX
// ("PUBLIC KEY") encoding, the inverse of ParseRSAPublicKeyFromPEM.
func EncodeRSAPublicKeyToPEM(key *rsa.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKeyType, err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// EncodeECPrivateKeyToPEM serializes an ECDSA private key to PEM using the SEC1
// ("EC PRIVATE KEY") encoding, the inverse of ParseECPrivateKeyFromPEM.
func EncodeECPrivateKeyToPEM(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKeyType, err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

// EncodeECPublicKeyToPEM serializes an ECDSA public key to PEM using the PKIX
// ("PUBLIC KEY") encoding, the inverse of ParseECPublicKeyFromPEM.
func EncodeECPublicKeyToPEM(key *ecdsa.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKeyType, err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// EncodeEdPrivateKeyToPEM serializes an Ed25519 private key to PEM using the
// PKCS#8 ("PRIVATE KEY") encoding, the inverse of ParseEdPrivateKeyFromPEM.
func EncodeEdPrivateKeyToPEM(key ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKeyType, err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// EncodeEdPublicKeyToPEM serializes an Ed25519 public key to PEM using the PKIX
// ("PUBLIC KEY") encoding, the inverse of ParseEdPublicKeyFromPEM.
func EncodeEdPublicKeyToPEM(key ed25519.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKeyType, err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// EncodePublicKeyToPEM serializes any supported public key (*rsa.PublicKey,
// *ecdsa.PublicKey, or ed25519.PublicKey) to a PKIX ("PUBLIC KEY") PEM block. It
// is the general-purpose counterpart to the type-specific encoders above.
func EncodePublicKeyToPEM(pub crypto.PublicKey) ([]byte, error) {
	switch pub.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
	default:
		return nil, fmt.Errorf("%w: unsupported public key type %T", ErrInvalidKeyType, pub)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKeyType, err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// EncodePrivateKeyToPEM serializes any supported private key (*rsa.PrivateKey,
// *ecdsa.PrivateKey, or ed25519.PrivateKey) to a PKCS#8 ("PRIVATE KEY") PEM
// block. Unlike the type-specific encoders, it always uses PKCS#8, giving a
// single uniform private-key file format across algorithms.
func EncodePrivateKeyToPEM(key crypto.PrivateKey) ([]byte, error) {
	switch key.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
	default:
		return nil, fmt.Errorf("%w: unsupported private key type %T", ErrInvalidKeyType, key)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKeyType, err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}
