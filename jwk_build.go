package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
)

// NewJSONWebKey constructs a JSONWebKey (RFC 7517) from a Go crypto key,
// populating the JSON parameters ("n", "e", "x", "y", "d", "crv", "k", ...) that
// correspond to the key's type. It is the inverse of ParseJWK, letting a service
// publish its verification keys as a JWK or JWKS.
//
// The supported key types are:
//
//	*rsa.PublicKey / *rsa.PrivateKey        -> kty "RSA"
//	*ecdsa.PublicKey / *ecdsa.PrivateKey    -> kty "EC"  (P-256, P-384, P-521)
//	ed25519.PublicKey / ed25519.PrivateKey  -> kty "OKP" (crv Ed25519)
//	[]byte                                  -> kty "oct"
//
// Coordinate and modulus fields use unpadded base64url with the fixed octet
// lengths required by RFC 7518. The resolved key is stored in the Key field, so
// the returned JWK round-trips through ParseJWK. Use the chainable WithKeyID,
// WithAlgorithm, and WithUse to annotate the key.
func NewJSONWebKey(key any) (*JSONWebKey, error) {
	switch k := key.(type) {
	case *rsa.PublicKey:
		return jwkbFromRSAPublic(k), nil
	case *rsa.PrivateKey:
		j := jwkbFromRSAPublic(&k.PublicKey)
		j.D = jwkbB64(k.D.Bytes())
		if len(k.Primes) >= 2 {
			j.P = jwkbB64(k.Primes[0].Bytes())
			j.Q = jwkbB64(k.Primes[1].Bytes())
		}
		if k.Precomputed.Dp != nil {
			j.Dp = jwkbB64(k.Precomputed.Dp.Bytes())
			j.Dq = jwkbB64(k.Precomputed.Dq.Bytes())
			j.Qi = jwkbB64(k.Precomputed.Qinv.Bytes())
		}
		j.Key = k
		return j, nil
	case *ecdsa.PublicKey:
		return jwkbFromECPublic(k)
	case *ecdsa.PrivateKey:
		j, err := jwkbFromECPublic(&k.PublicKey)
		if err != nil {
			return nil, err
		}
		size := (k.Curve.Params().BitSize + 7) / 8
		j.D = jwkbB64(jwkbPad(k.D, size))
		j.Key = k
		return j, nil
	case ed25519.PublicKey:
		return jwkbFromEdPublic(k)
	case ed25519.PrivateKey:
		pub, ok := k.Public().(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("%w: invalid ed25519 private key", ErrInvalidKey)
		}
		j, err := jwkbFromEdPublic(pub)
		if err != nil {
			return nil, err
		}
		j.D = jwkbB64(k.Seed())
		j.Key = k
		return j, nil
	case []byte:
		if len(k) == 0 {
			return nil, fmt.Errorf("%w: empty oct key", ErrInvalidKey)
		}
		return &JSONWebKey{Kty: "oct", K: jwkbB64(k), Key: k}, nil
	default:
		return nil, fmt.Errorf("%w: unsupported key type %T", ErrInvalidKey, key)
	}
}

// ComputeKeyID derives a stable key identifier from a Go crypto key: the
// base64url-encoded SHA-256 RFC 7638 thumbprint of the key's public part. Using
// it as the "kid" gives every key a deterministic, collision-resistant name
// that both signer and verifier can compute independently.
func ComputeKeyID(key any) (string, error) {
	j, err := NewJSONWebKey(key)
	if err != nil {
		return "", err
	}
	return j.Public().Base64Thumbprint(crypto.SHA256)
}

// Base64Thumbprint returns the RFC 7638 JWK thumbprint of the key encoded as
// unpadded base64url, the textual form conventionally used as a "kid".
func (j *JSONWebKey) Base64Thumbprint(h crypto.Hash) (string, error) {
	sum, err := j.Thumbprint(h)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(sum), nil
}

// ThumbprintURI returns the RFC 9278 JWK Thumbprint URI for the key, of the form
// "urn:ietf:params:oauth:jwk-thumbprint:sha-256:<base64url>". Only SHA-256,
// SHA-384, and SHA-512 have registered hash names; other hashes yield an error.
func (j *JSONWebKey) ThumbprintURI(h crypto.Hash) (string, error) {
	name, ok := jwkbHashName[h]
	if !ok {
		return "", fmt.Errorf("%w: hash has no registered thumbprint name", ErrHashUnavailable)
	}
	b64, err := j.Base64Thumbprint(h)
	if err != nil {
		return "", err
	}
	return "urn:ietf:params:oauth:jwk-thumbprint:" + name + ":" + b64, nil
}

// WithKeyID sets the JWK "kid" (key ID) and returns the receiver for chaining.
func (j *JSONWebKey) WithKeyID(kid string) *JSONWebKey {
	j.Kid = kid
	return j
}

// WithAlgorithm sets the JWK "alg" (intended algorithm, e.g. "RS256") and
// returns the receiver for chaining.
func (j *JSONWebKey) WithAlgorithm(alg string) *JSONWebKey {
	j.Alg = alg
	return j
}

// WithUse sets the JWK "use" (public key use, "sig" or "enc") and returns the
// receiver for chaining.
func (j *JSONWebKey) WithUse(use string) *JSONWebKey {
	j.Use = use
	return j
}

// Add appends keys to the set and returns the receiver for chaining, making it
// convenient to assemble a JWKS document for publication.
func (s *JSONWebKeySet) Add(keys ...JSONWebKey) *JSONWebKeySet {
	s.Keys = append(s.Keys, keys...)
	return s
}

// jwkbHashName maps a hash to its IANA "Hash Name String" used in RFC 9278
// thumbprint URIs.
var jwkbHashName = map[crypto.Hash]string{
	crypto.SHA256: "sha-256",
	crypto.SHA384: "sha-384",
	crypto.SHA512: "sha-512",
}

// jwkbB64 encodes b as unpadded base64url.
func jwkbB64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// jwkbPad returns the big-endian bytes of n left-padded with zeros to size
// octets, as RFC 7518 requires for fixed-width EC fields.
func jwkbPad(n *big.Int, size int) []byte {
	b := make([]byte, size)
	n.FillBytes(b)
	return b
}

func jwkbFromRSAPublic(k *rsa.PublicKey) *JSONWebKey {
	e := big.NewInt(int64(k.E))
	return &JSONWebKey{
		Kty: "RSA",
		N:   jwkbB64(k.N.Bytes()),
		E:   jwkbB64(e.Bytes()),
		Key: k,
	}
}

func jwkbFromECPublic(k *ecdsa.PublicKey) (*JSONWebKey, error) {
	crv, err := jwkbCurveName(k)
	if err != nil {
		return nil, err
	}
	size := (k.Curve.Params().BitSize + 7) / 8
	return &JSONWebKey{
		Kty: "EC",
		Crv: crv,
		X:   jwkbB64(jwkbPad(k.X, size)),
		Y:   jwkbB64(jwkbPad(k.Y, size)),
		Key: k,
	}, nil
}

func jwkbFromEdPublic(k ed25519.PublicKey) (*JSONWebKey, error) {
	if len(k) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: ed25519 public key has wrong length %d", ErrInvalidKey, len(k))
	}
	return &JSONWebKey{
		Kty: "OKP",
		Crv: "Ed25519",
		X:   jwkbB64(k),
		Key: k,
	}, nil
}

// jwkbCurveName returns the JWK "crv" name for an EC public key's curve.
func jwkbCurveName(k *ecdsa.PublicKey) (string, error) {
	switch k.Curve.Params().Name {
	case "P-256":
		return "P-256", nil
	case "P-384":
		return "P-384", nil
	case "P-521":
		return "P-521", nil
	default:
		return "", fmt.Errorf("%w: unsupported EC curve %q", ErrInvalidKey, k.Curve.Params().Name)
	}
}
