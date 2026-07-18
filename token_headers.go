package jwt

// SetHeader sets an arbitrary JOSE header parameter and returns the token for
// chaining. It is the general form of SetKID; use it to add headers such as
// "cty", "x5t", or a custom extension before signing. The header map is
// allocated if the token does not yet have one.
func (t *Token) SetHeader(key string, value any) *Token {
	if t.Header == nil {
		t.Header = map[string]any{}
	}
	t.Header[key] = value
	return t
}

// SetType sets the JOSE "typ" header (for example "JWT" or "at+jwt") and returns
// the token for chaining.
func (t *Token) SetType(typ string) *Token {
	return t.SetHeader("typ", typ)
}

// KeyID returns the token's "kid" header as a string, or "" if it is absent or
// not a string. It is the read counterpart to SetKID and is convenient after
// ParseUnverified to select a verification key.
func (t *Token) KeyID() string {
	return t.HeaderString("kid")
}

// TokenType returns the token's "typ" header as a string, or "" if it is absent
// or not a string.
func (t *Token) TokenType() string {
	return t.HeaderString("typ")
}

// HeaderString returns the header parameter key as a string, or "" if it is
// absent or not a string.
func (t *Token) HeaderString(key string) string {
	if t.Header == nil {
		return ""
	}
	if s, ok := t.Header[key].(string); ok {
		return s
	}
	return ""
}
