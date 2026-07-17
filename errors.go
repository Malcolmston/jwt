package jwt

import "errors"

// Sentinel errors returned by the package. Callers may test for these using
// errors.Is. Parsing and validation errors are typically wrapped so that a
// single returned error can match several of these categories.
var (
	// ErrInvalidToken is a generic error indicating the token could not be
	// parsed or is otherwise malformed.
	ErrInvalidToken = errors.New("jwt: token is invalid")

	// ErrTokenMalformed indicates the compact serialization did not have the
	// expected three dot-separated parts, or a part failed to decode.
	ErrTokenMalformed = errors.New("jwt: token is malformed")

	// ErrSignatureInvalid indicates the signature failed verification.
	ErrSignatureInvalid = errors.New("jwt: signature is invalid")

	// ErrTokenUnverifiable indicates the keyFunc returned an error or no key.
	ErrTokenUnverifiable = errors.New("jwt: token is unverifiable")

	// ErrInvalidKeyType indicates the key supplied to a signing method was not
	// of the type that method requires.
	ErrInvalidKeyType = errors.New("jwt: key is of invalid type")

	// ErrHashUnavailable indicates the requested hash function is not linked
	// into the binary.
	ErrHashUnavailable = errors.New("jwt: the requested hash function is unavailable")

	// ErrSigningMethodUnavailable indicates the alg header referenced a method
	// that has not been registered.
	ErrSigningMethodUnavailable = errors.New("jwt: signing method is unavailable")

	// Validation errors.

	// ErrTokenExpired indicates the exp claim is in the past.
	ErrTokenExpired = errors.New("jwt: token is expired")

	// ErrTokenNotValidYet indicates the nbf claim is in the future.
	ErrTokenNotValidYet = errors.New("jwt: token is not valid yet")

	// ErrTokenUsedBeforeIssued indicates the iat claim is in the future.
	ErrTokenUsedBeforeIssued = errors.New("jwt: token used before issued")

	// ErrTokenInvalidAudience indicates the aud claim did not contain the
	// expected audience.
	ErrTokenInvalidAudience = errors.New("jwt: token has invalid audience")

	// ErrTokenInvalidIssuer indicates the iss claim did not match the expected
	// issuer.
	ErrTokenInvalidIssuer = errors.New("jwt: token has invalid issuer")

	// ErrTokenInvalidSubject indicates the sub claim did not match the expected
	// subject.
	ErrTokenInvalidSubject = errors.New("jwt: token has invalid subject")

	// ErrTokenRequiredClaimMissing indicates a claim required by parser options
	// was absent.
	ErrTokenRequiredClaimMissing = errors.New("jwt: token is missing a required claim")

	// ErrInvalidType indicates a claim held a value of an unexpected JSON type.
	ErrInvalidType = errors.New("jwt: invalid type for claim")

	// ErrNoneAlgDisallowed indicates a token used the "none" algorithm but the
	// parser was not configured to accept unsecured tokens.
	ErrNoneAlgDisallowed = errors.New("jwt: 'none' signature type is not allowed")

	// ErrInvalidKey indicates a JWK could not be decoded into a usable key, or
	// held inconsistent parameters.
	ErrInvalidKey = errors.New("jwt: key is invalid")

	// ErrKeyNotFound indicates a JWKS did not contain a key matching the
	// requested key ID.
	ErrKeyNotFound = errors.New("jwt: no key found for kid")

	// ErrTokenTooOld indicates the token's age (now minus iat) exceeds the
	// maximum permitted by WithMaxTokenAge.
	ErrTokenTooOld = errors.New("jwt: token is older than the maximum allowed age")

	// ErrInvalidCrit indicates the JOSE "crit" header referenced an extension
	// the parser does not understand, or was itself malformed.
	ErrInvalidCrit = errors.New("jwt: unsupported or malformed 'crit' header")

	// ErrInvalidTyp indicates the JOSE "typ" header did not match one of the
	// types required by WithValidTypes.
	ErrInvalidTyp = errors.New("jwt: token has invalid 'typ' header")

	// ErrJWKSFetch indicates a JWKS could not be fetched or refreshed from its
	// remote endpoint.
	ErrJWKSFetch = errors.New("jwt: could not fetch JWKS")
)
