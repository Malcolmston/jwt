package jwt

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// hmacSecret extracts the symmetric secret an HS* signing method must use, or
// reports why the supplied key cannot serve as one.
//
// It mirrors two behaviors of node's jsonwebtoken: the algorithm family is
// inferred from the key material, and an HS* operation additionally insists on a
// symmetric key. Concretely, asymmetric key material — a typed *rsa.PublicKey,
// *ecdsa.PublicKey, ed25519.PublicKey (or their private counterparts), or bytes
// holding a PEM block, a bare DER key, or a certificate — is refused with
// ErrAsymmetricKeyForHMAC instead of being MACed as if it were a shared secret.
// Without that refusal an attacker who knows the verifier's public key (which is
// public by definition) can mint an HS256 token keyed with those very bytes and
// have it accepted: the classic algorithm-confusion attack.
func hmacSecret(key any) ([]byte, error) {
	switch k := key.(type) {
	case []byte:
		if err := rejectAsymmetricBytes(k); err != nil {
			return nil, err
		}
		return k, nil
	case *rsa.PublicKey, *rsa.PrivateKey,
		*ecdsa.PublicKey, *ecdsa.PrivateKey,
		ed25519.PublicKey, ed25519.PrivateKey,
		*ecdh.PublicKey, *ecdh.PrivateKey:
		return nil, fmt.Errorf("%w: got %T", ErrAsymmetricKeyForHMAC, key)
	default:
		return nil, fmt.Errorf("%w: HMAC requires []byte, got %T", ErrInvalidKeyType, key)
	}
}

// rejectAsymmetricBytes returns ErrAsymmetricKeyForHMAC if b holds encoded
// asymmetric key material rather than an opaque symmetric secret. PEM is checked
// first (it is what callers most often mistakenly pass), then the bytes are
// tried as bare DER.
func rejectAsymmetricBytes(b []byte) error {
	if block, _ := pem.Decode(b); block != nil {
		return fmt.Errorf("%w: got a PEM %q block", ErrAsymmetricKeyForHMAC, block.Type)
	}
	if isAsymmetricDER(b) {
		return fmt.Errorf("%w: got DER-encoded key material", ErrAsymmetricKeyForHMAC)
	}
	return nil
}

// isAsymmetricDER reports whether der parses as any of the DER encodings this
// package uses for asymmetric keys or certificates.
func isAsymmetricDER(der []byte) bool {
	if _, err := x509.ParsePKIXPublicKey(der); err == nil {
		return true
	}
	if _, err := x509.ParsePKCS1PublicKey(der); err == nil {
		return true
	}
	if _, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return true
	}
	if _, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return true
	}
	if _, err := x509.ParseECPrivateKey(der); err == nil {
		return true
	}
	if _, err := x509.ParseCertificate(der); err == nil {
		return true
	}
	return false
}
