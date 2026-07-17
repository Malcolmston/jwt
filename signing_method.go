package jwt

import "sync"

// SigningMethod defines the interface implemented by every algorithm the
// library supports. Alg returns the value written to the JOSE "alg" header,
// Sign produces a signature over the signing input, and Verify checks a
// signature against that input.
type SigningMethod interface {
	// Alg returns the JWS "alg" header value, e.g. "HS256" or "ES384".
	Alg() string

	// Sign signs signingString (the base64url header + "." + base64url
	// payload) with key and returns the raw signature bytes. The key type
	// depends on the method (e.g. []byte for HMAC, *rsa.PrivateKey for RSA).
	Sign(signingString string, key any) ([]byte, error)

	// Verify checks that sig is a valid signature over signingString using
	// key. It returns nil on success and a non-nil error (wrapping
	// ErrSignatureInvalid) on failure.
	Verify(signingString string, sig []byte, key any) error
}

var (
	signingMethods   = map[string]func() SigningMethod{}
	signingMethodsMu sync.RWMutex
)

// RegisterSigningMethod registers alg so it can be resolved by GetSigningMethod
// and by the parser. It is safe for concurrent use. Registering the same alg
// twice replaces the prior registration.
func RegisterSigningMethod(alg string, f func() SigningMethod) {
	signingMethodsMu.Lock()
	defer signingMethodsMu.Unlock()
	signingMethods[alg] = f
}

// GetSigningMethod returns the SigningMethod registered for alg, or nil if none
// is registered.
func GetSigningMethod(alg string) SigningMethod {
	signingMethodsMu.RLock()
	defer signingMethodsMu.RUnlock()
	if f, ok := signingMethods[alg]; ok {
		return f()
	}
	return nil
}

// GetAlgorithms returns the sorted-order-independent list of registered alg
// identifiers. It is primarily useful for diagnostics and tests.
func GetAlgorithms() []string {
	signingMethodsMu.RLock()
	defer signingMethodsMu.RUnlock()
	out := make([]string, 0, len(signingMethods))
	for alg := range signingMethods {
		out = append(out, alg)
	}
	return out
}
