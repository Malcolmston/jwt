package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
)

// JSONWebKey represents a single JSON Web Key (RFC 7517). It carries the raw
// JWK parameters as decoded from JSON and, after ParseJWK (or Parse on a set),
// the corresponding Go crypto key in Key.
//
// The supported key types ("kty") are:
//
//	RSA  – *rsa.PublicKey / *rsa.PrivateKey
//	EC   – *ecdsa.PublicKey / *ecdsa.PrivateKey (curves P-256, P-384, P-521)
//	OKP  – ed25519.PublicKey / ed25519.PrivateKey (curve Ed25519)
//	oct  – []byte (a symmetric secret)
type JSONWebKey struct {
	// Key holds the parsed Go crypto key (see the type list above). It is
	// populated by ParseJWK and by JSONWebKeySet parsing; it is nil on a JWK
	// that was only unmarshaled as JSON.
	Key any `json:"-"`

	// Kty is the key type: "RSA", "EC", "OKP", or "oct".
	Kty string `json:"kty"`
	// Use is the intended public key use, "sig" or "enc" (optional).
	Use string `json:"use,omitempty"`
	// KeyOps lists the permitted key operations (optional).
	KeyOps []string `json:"key_ops,omitempty"`
	// Alg is the algorithm intended for use with the key, e.g. "RS256".
	Alg string `json:"alg,omitempty"`
	// Kid is the key ID used to match a JWK against a token's "kid" header.
	Kid string `json:"kid,omitempty"`

	// RSA public parameters.
	N string `json:"n,omitempty"` // modulus
	E string `json:"e,omitempty"` // public exponent
	// RSA private parameters.
	D  string `json:"d,omitempty"`  // private exponent (also EC/OKP private key)
	P  string `json:"p,omitempty"`  // first prime factor
	Q  string `json:"q,omitempty"`  // second prime factor
	Dp string `json:"dp,omitempty"` // d mod (p-1)
	Dq string `json:"dq,omitempty"` // d mod (q-1)
	Qi string `json:"qi,omitempty"` // q^-1 mod p

	// EC / OKP parameters.
	Crv string `json:"crv,omitempty"` // curve, e.g. "P-256" or "Ed25519"
	X   string `json:"x,omitempty"`   // x coordinate (EC) or public key (OKP)
	Y   string `json:"y,omitempty"`   // y coordinate (EC)

	// oct parameter.
	K string `json:"k,omitempty"` // symmetric key material
}

// JSONWebKeySet is a set of JSON Web Keys (RFC 7517 §5), the "jwks" document
// commonly served at a provider's well-known endpoint.
type JSONWebKeySet struct {
	Keys []JSONWebKey `json:"keys"`
}

// b64uint decodes a base64url (no padding) big-endian unsigned integer field.
func b64uint(s string) (*big.Int, error) {
	b, err := b64bytes(s)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}

// b64bytes decodes a base64url field, tolerating optional padding.
func b64bytes(s string) ([]byte, error) {
	if s == "" {
		return nil, fmt.Errorf("%w: empty JWK field", ErrInvalidKey)
	}
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}

// ParseJWK decodes a single JWK from its JSON encoding and resolves its Go
// crypto key into the returned key's Key field.
func ParseJWK(data []byte) (*JSONWebKey, error) {
	var jwk JSONWebKey
	if err := json.Unmarshal(data, &jwk); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	if err := jwk.parse(); err != nil {
		return nil, err
	}
	return &jwk, nil
}

// ParseJWKSet decodes a JWKS (JSON Web Key Set) document and resolves the Go
// crypto key for every contained JWK.
func ParseJWKSet(data []byte) (*JSONWebKeySet, error) {
	var set JSONWebKeySet
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	for i := range set.Keys {
		if err := set.Keys[i].parse(); err != nil {
			return nil, fmt.Errorf("key %d (kid %q): %w", i, set.Keys[i].Kid, err)
		}
	}
	return &set, nil
}

// UnmarshalJSON decodes the JWK JSON parameters and resolves the crypto key.
func (j *JSONWebKey) UnmarshalJSON(data []byte) error {
	type alias JSONWebKey // avoid recursion
	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	*j = JSONWebKey(a)
	return j.parse()
}

// MarshalJSON encodes the JWK parameters (not the resolved Key) as JSON.
func (j JSONWebKey) MarshalJSON() ([]byte, error) {
	type alias JSONWebKey
	return json.Marshal(alias(j))
}

// parse resolves j.Key from the decoded parameters according to j.Kty.
func (j *JSONWebKey) parse() error {
	switch j.Kty {
	case "RSA":
		return j.parseRSA()
	case "EC":
		return j.parseEC()
	case "OKP":
		return j.parseOKP()
	case "oct":
		return j.parseOct()
	case "":
		return fmt.Errorf("%w: missing kty", ErrInvalidKey)
	default:
		return fmt.Errorf("%w: unsupported kty %q", ErrInvalidKey, j.Kty)
	}
}

func (j *JSONWebKey) parseRSA() error {
	n, err := b64uint(j.N)
	if err != nil {
		return fmt.Errorf("%w: rsa n: %v", ErrInvalidKey, err)
	}
	e, err := b64uint(j.E)
	if err != nil {
		return fmt.Errorf("%w: rsa e: %v", ErrInvalidKey, err)
	}
	pub := &rsa.PublicKey{N: n, E: int(e.Int64())}
	if j.D == "" {
		j.Key = pub
		return nil
	}
	d, err := b64uint(j.D)
	if err != nil {
		return fmt.Errorf("%w: rsa d: %v", ErrInvalidKey, err)
	}
	priv := &rsa.PrivateKey{PublicKey: *pub, D: d}
	if j.P != "" && j.Q != "" {
		p, err := b64uint(j.P)
		if err != nil {
			return fmt.Errorf("%w: rsa p: %v", ErrInvalidKey, err)
		}
		q, err := b64uint(j.Q)
		if err != nil {
			return fmt.Errorf("%w: rsa q: %v", ErrInvalidKey, err)
		}
		priv.Primes = []*big.Int{p, q}
	}
	if err := priv.Validate(); err != nil {
		return fmt.Errorf("%w: rsa key: %v", ErrInvalidKey, err)
	}
	priv.Precompute()
	j.Key = priv
	return nil
}

// ecCurve maps a JWK "crv" name to a standard elliptic curve.
func ecCurve(name string) (elliptic.Curve, error) {
	switch name {
	case "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("%w: unsupported EC curve %q", ErrInvalidKey, name)
	}
}

func (j *JSONWebKey) parseEC() error {
	curve, err := ecCurve(j.Crv)
	if err != nil {
		return err
	}
	x, err := b64uint(j.X)
	if err != nil {
		return fmt.Errorf("%w: ec x: %v", ErrInvalidKey, err)
	}
	y, err := b64uint(j.Y)
	if err != nil {
		return fmt.Errorf("%w: ec y: %v", ErrInvalidKey, err)
	}
	if !curve.IsOnCurve(x, y) {
		return fmt.Errorf("%w: EC point is not on curve %s", ErrInvalidKey, j.Crv)
	}
	pub := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
	if j.D == "" {
		j.Key = pub
		return nil
	}
	d, err := b64uint(j.D)
	if err != nil {
		return fmt.Errorf("%w: ec d: %v", ErrInvalidKey, err)
	}
	j.Key = &ecdsa.PrivateKey{PublicKey: *pub, D: d}
	return nil
}

func (j *JSONWebKey) parseOKP() error {
	if j.Crv != "Ed25519" {
		return fmt.Errorf("%w: unsupported OKP curve %q", ErrInvalidKey, j.Crv)
	}
	x, err := b64bytes(j.X)
	if err != nil {
		return fmt.Errorf("%w: okp x: %v", ErrInvalidKey, err)
	}
	if len(x) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: ed25519 public key has wrong length %d", ErrInvalidKey, len(x))
	}
	if j.D == "" {
		j.Key = ed25519.PublicKey(x)
		return nil
	}
	d, err := b64bytes(j.D)
	if err != nil {
		return fmt.Errorf("%w: okp d: %v", ErrInvalidKey, err)
	}
	if len(d) != ed25519.SeedSize {
		return fmt.Errorf("%w: ed25519 seed has wrong length %d", ErrInvalidKey, len(d))
	}
	j.Key = ed25519.NewKeyFromSeed(d)
	return nil
}

func (j *JSONWebKey) parseOct() error {
	k, err := b64bytes(j.K)
	if err != nil {
		return fmt.Errorf("%w: oct k: %v", ErrInvalidKey, err)
	}
	j.Key = k
	return nil
}

// IsPrivate reports whether the resolved key is a private (signing) key.
func (j *JSONWebKey) IsPrivate() bool {
	switch j.Key.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
		return true
	default:
		return false
	}
}

// Public returns a JWK holding only the public part of the key. For a symmetric
// ("oct") key, which has no public form, it returns the receiver unchanged.
func (j *JSONWebKey) Public() *JSONWebKey {
	if j.Key == nil || !j.IsPrivate() {
		return j
	}
	pub := *j
	pub.D, pub.P, pub.Q, pub.Dp, pub.Dq, pub.Qi = "", "", "", "", "", ""
	switch k := j.Key.(type) {
	case *rsa.PrivateKey:
		pub.Key = &k.PublicKey
	case *ecdsa.PrivateKey:
		pub.Key = &k.PublicKey
	case ed25519.PrivateKey:
		pub.Key = k.Public().(ed25519.PublicKey)
	}
	return &pub
}

// Thumbprint returns the RFC 7638 JWK thumbprint of the key, computed with the
// given hash (SHA-256 is the conventional choice). The thumbprint is derived
// from the canonical, minimal set of required members for the key type, encoded
// as lexicographically ordered compact JSON, and is stable across
// implementations. The raw hash digest is returned; base64url-encode it for a
// textual identifier.
func (j *JSONWebKey) Thumbprint(h crypto.Hash) ([]byte, error) {
	if !h.Available() {
		return nil, ErrHashUnavailable
	}
	var canonical string
	switch j.Kty {
	case "RSA":
		if j.E == "" || j.N == "" {
			return nil, fmt.Errorf("%w: rsa thumbprint needs n and e", ErrInvalidKey)
		}
		canonical = fmt.Sprintf(`{"e":%q,"kty":"RSA","n":%q}`, j.E, j.N)
	case "EC":
		if j.Crv == "" || j.X == "" || j.Y == "" {
			return nil, fmt.Errorf("%w: ec thumbprint needs crv, x and y", ErrInvalidKey)
		}
		canonical = fmt.Sprintf(`{"crv":%q,"kty":"EC","x":%q,"y":%q}`, j.Crv, j.X, j.Y)
	case "OKP":
		if j.Crv == "" || j.X == "" {
			return nil, fmt.Errorf("%w: okp thumbprint needs crv and x", ErrInvalidKey)
		}
		canonical = fmt.Sprintf(`{"crv":%q,"kty":"OKP","x":%q}`, j.Crv, j.X)
	case "oct":
		if j.K == "" {
			return nil, fmt.Errorf("%w: oct thumbprint needs k", ErrInvalidKey)
		}
		canonical = fmt.Sprintf(`{"k":%q,"kty":"oct"}`, j.K)
	default:
		return nil, fmt.Errorf("%w: cannot thumbprint kty %q", ErrInvalidKey, j.Kty)
	}
	hasher := h.New()
	hasher.Write([]byte(canonical))
	return hasher.Sum(nil), nil
}

// LookupKeyID returns every key in the set whose Kid equals kid. A JWKS may
// legitimately contain more than one key for a kid during key rotation.
func (s *JSONWebKeySet) LookupKeyID(kid string) []JSONWebKey {
	var out []JSONWebKey
	for _, k := range s.Keys {
		if k.Kid == kid {
			out = append(out, k)
		}
	}
	return out
}

// Key returns the single resolved crypto key in the set matching kid. It fails
// with ErrKeyNotFound if no key matches, and with ErrInvalidKey if more than
// one key shares the kid (ambiguous). When the set holds exactly one key and
// kid is empty, that key is returned.
func (s *JSONWebKeySet) Key(kid string) (any, error) {
	if kid == "" && len(s.Keys) == 1 {
		return s.Keys[0].Key, nil
	}
	matches := s.LookupKeyID(kid)
	switch len(matches) {
	case 0:
		return nil, fmt.Errorf("%w: kid %q", ErrKeyNotFound, kid)
	case 1:
		return matches[0].Key, nil
	default:
		return nil, fmt.Errorf("%w: multiple keys for kid %q", ErrInvalidKey, kid)
	}
}

// Keyfunc returns a Keyfunc that resolves the verification key from the set by
// the token's "kid" header. It also enforces that the JWK's declared "alg"
// (when present) matches the token's alg header, an additional guard against
// algorithm confusion.
func (s *JSONWebKeySet) Keyfunc() Keyfunc {
	return func(token *Token) (any, error) {
		kid, _ := token.Header["kid"].(string)
		alg, _ := token.Header["alg"].(string)
		matches := s.LookupKeyID(kid)
		if kid == "" && len(s.Keys) == 1 {
			matches = s.Keys
		}
		switch len(matches) {
		case 0:
			return nil, fmt.Errorf("%w: kid %q", ErrKeyNotFound, kid)
		case 1:
			jwk := matches[0]
			if jwk.Alg != "" && alg != "" && jwk.Alg != alg {
				return nil, fmt.Errorf("%w: JWK alg %q does not match token alg %q", ErrSignatureInvalid, jwk.Alg, alg)
			}
			return jwk.Key, nil
		default:
			// Disambiguate by alg when several keys share the kid.
			for _, jwk := range matches {
				if jwk.Alg == alg {
					return jwk.Key, nil
				}
			}
			return nil, fmt.Errorf("%w: multiple keys for kid %q", ErrInvalidKey, kid)
		}
	}
}
