package jwt

import "fmt"

// unsafeNoneMagic is the sentinel key that must be passed to the "none" signing
// method to acknowledge that an unsecured token is being produced or verified.
// This makes accidental use of "none" impossible.
type unsafeNoneMagic struct{}

// UnsafeAllowNoneSignatureType is the only key value accepted by the "none"
// signing method. Its type makes the opt-in explicit and greppable.
var UnsafeAllowNoneSignatureType any = unsafeNoneMagic{}

// SigningMethodNone implements the unsecured "none" algorithm from RFC 7515.
// It produces an empty signature. To guard against the classic algorithm-
// confusion attack, both Sign and Verify require the caller to pass
// UnsafeAllowNoneSignatureType as the key.
type SigningMethodNone struct{}

// SigningMethodNoneAlg is the shared instance of the "none" method.
var SigningMethodNoneAlg = &SigningMethodNone{}

func init() {
	RegisterSigningMethod("none", func() SigningMethod { return SigningMethodNoneAlg })
}

// Alg returns "none".
func (m *SigningMethodNone) Alg() string { return "none" }

// Sign returns an empty signature. key must be UnsafeAllowNoneSignatureType.
func (m *SigningMethodNone) Sign(_ string, key any) ([]byte, error) {
	if _, ok := key.(unsafeNoneMagic); !ok {
		return nil, fmt.Errorf("%w: 'none' requires jwt.UnsafeAllowNoneSignatureType", ErrNoneAlgDisallowed)
	}
	return []byte{}, nil
}

// Verify accepts only an empty signature and only when key is
// UnsafeAllowNoneSignatureType.
func (m *SigningMethodNone) Verify(_ string, sig []byte, key any) error {
	if _, ok := key.(unsafeNoneMagic); !ok {
		return fmt.Errorf("%w: 'none' requires jwt.UnsafeAllowNoneSignatureType", ErrNoneAlgDisallowed)
	}
	if len(sig) != 0 {
		return ErrSignatureInvalid
	}
	return nil
}
