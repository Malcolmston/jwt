package jwt

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// ErrKeyMustBePEMEncoded is returned when the input is not valid PEM.
var ErrKeyMustBePEMEncoded = fmt.Errorf("%w: key must be PEM encoded", ErrInvalidKeyType)

// ParseRSAPrivateKeyFromPEM parses a PEM-encoded RSA private key in either
// PKCS#1 ("RSA PRIVATE KEY") or PKCS#8 ("PRIVATE KEY") form.
func ParseRSAPrivateKeyFromPEM(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, ErrKeyMustBePEMEncoded
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKeyType, err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w: not an RSA private key", ErrInvalidKeyType)
	}
	return key, nil
}

// ParseRSAPublicKeyFromPEM parses a PEM-encoded RSA public key, accepting both
// PKIX ("PUBLIC KEY") and PKCS#1 ("RSA PUBLIC KEY") forms, and also a
// certificate ("CERTIFICATE") whose public key is RSA.
func ParseRSAPublicKeyFromPEM(pemBytes []byte) (*rsa.PublicKey, error) {
	pub, err := parsePublicKeyFromPEM(pemBytes)
	if err != nil {
		return nil, err
	}
	key, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: not an RSA public key", ErrInvalidKeyType)
	}
	return key, nil
}

// ParseECPrivateKeyFromPEM parses a PEM-encoded EC private key in either SEC1
// ("EC PRIVATE KEY") or PKCS#8 ("PRIVATE KEY") form.
func ParseECPrivateKeyFromPEM(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, ErrKeyMustBePEMEncoded
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKeyType, err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w: not an EC private key", ErrInvalidKeyType)
	}
	return key, nil
}

// ParseECPublicKeyFromPEM parses a PEM-encoded EC public key (PKIX
// "PUBLIC KEY") or a certificate whose public key is EC.
func ParseECPublicKeyFromPEM(pemBytes []byte) (*ecdsa.PublicKey, error) {
	pub, err := parsePublicKeyFromPEM(pemBytes)
	if err != nil {
		return nil, err
	}
	key, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: not an EC public key", ErrInvalidKeyType)
	}
	return key, nil
}

// parsePublicKeyFromPEM decodes a PEM block and returns the enclosed public
// key, handling PKIX, PKCS#1, and certificate encodings.
func parsePublicKeyFromPEM(pemBytes []byte) (any, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, ErrKeyMustBePEMEncoded
	}
	if pub, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		return pub, nil
	}
	if key, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return key, nil
	}
	if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
		return cert.PublicKey, nil
	}
	return nil, fmt.Errorf("%w: unsupported public key encoding", ErrInvalidKeyType)
}
