package jwt

import (
	"encoding/json"
	"fmt"
	"strings"
)

// SignDetached produces a detached JWS with an unencoded payload, per RFC 7797
// (the "b64":false option). The payload is signed as-is (not base64url-encoded)
// and is omitted from the returned compact serialization, which has the form
//
//	BASE64URL(header) + ".." + BASE64URL(signature)
//
// The synthesized header sets "alg", "b64":false, and "crit":["b64"]; any
// entries in extraHeaders (e.g. "kid") are merged in first. Recipients must
// supply the same payload out of band and verify with VerifyDetached.
func SignDetached(payload []byte, method SigningMethod, key any, extraHeaders map[string]any) (string, error) {
	header := map[string]any{}
	for k, v := range extraHeaders {
		header[k] = v
	}
	header["alg"] = method.Alg()
	header["b64"] = false
	header["crit"] = []any{"b64"}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("%w: encoding header: %v", ErrInvalidToken, err)
	}
	encHeader := EncodeSegment(headerJSON)

	signingInput := encHeader + "." + string(payload)
	sig, err := method.Sign(signingInput, key)
	if err != nil {
		return "", err
	}
	// Detached form: the middle (payload) segment is empty.
	return encHeader + ".." + EncodeSegment(sig), nil
}

// VerifyDetached verifies a detached JWS produced with an unencoded payload
// (RFC 7797). jws is the "BASE64URL(header)..BASE64URL(signature)"
// serialization and payload is the detached payload supplied out of band.
// keyFunc resolves the verification key from the decoded header.
//
// Parser options that concern algorithm selection are honored: WithValidMethods
// restricts the accepted alg (the primary algorithm-confusion defense) and
// WithAllowNone is required to accept alg "none". Claim validation options do
// not apply, since the payload is opaque bytes rather than JSON claims.
func VerifyDetached(jws string, payload []byte, keyFunc Keyfunc, opts ...ParserOption) (*Token, error) {
	p := NewParser(opts...)
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: expected 3 parts, got %d", ErrTokenMalformed, len(parts))
	}
	if parts[1] != "" {
		return nil, fmt.Errorf("%w: detached JWS must have an empty payload segment", ErrTokenMalformed)
	}

	token := &Token{Raw: jws}
	headerBytes, err := DecodeSegment(parts[0])
	if err != nil {
		return token, fmt.Errorf("%w: decoding header: %v", ErrTokenMalformed, err)
	}
	if err := json.Unmarshal(headerBytes, &token.Header); err != nil {
		return token, fmt.Errorf("%w: parsing header: %v", ErrTokenMalformed, err)
	}

	// The b64 header must be present and false, and listed as critical.
	if b64, ok := token.Header["b64"].(bool); !ok || b64 {
		return token, fmt.Errorf("%w: detached verify requires b64:false", ErrInvalidCrit)
	}
	if err := p.checkHeader(token); err != nil {
		return token, err
	}

	alg, _ := token.Header["alg"].(string)
	if len(p.validAlgs) > 0 && !contains(p.validAlgs, alg) {
		return token, fmt.Errorf("%w: alg %q is not accepted", ErrSignatureInvalid, alg)
	}
	if alg == "none" && !p.allowNone {
		return token, ErrNoneAlgDisallowed
	}
	method := GetSigningMethod(alg)
	if method == nil {
		return token, fmt.Errorf("%w: %q", ErrSigningMethodUnavailable, alg)
	}
	token.Method = method

	if keyFunc == nil {
		return token, fmt.Errorf("%w: no keyfunc provided", ErrTokenUnverifiable)
	}
	key, err := keyFunc(token)
	if err != nil {
		return token, fmt.Errorf("%w: %v", ErrTokenUnverifiable, err)
	}

	token.Signature, err = DecodeSegment(parts[2])
	if err != nil {
		return token, fmt.Errorf("%w: decoding signature: %v", ErrTokenMalformed, err)
	}

	signingInput := parts[0] + "." + string(payload)
	if err := method.Verify(signingInput, token.Signature, key); err != nil {
		return token, err
	}
	token.Valid = true
	return token, nil
}
