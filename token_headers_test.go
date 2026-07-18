package jwt

import "testing"

func TestTokenHeaderHelpers(t *testing.T) {
	tok := NewWithClaims(SigningMethodHS256, MapClaims{})
	tok.SetKID("key-1").SetType("at+jwt").SetHeader("cty", "example")

	if tok.KeyID() != "key-1" {
		t.Errorf("KeyID = %q", tok.KeyID())
	}
	if tok.TokenType() != "at+jwt" {
		t.Errorf("TokenType = %q", tok.TokenType())
	}
	if tok.HeaderString("cty") != "example" {
		t.Errorf("HeaderString cty = %q", tok.HeaderString("cty"))
	}
	if tok.HeaderString("missing") != "" {
		t.Errorf("HeaderString missing should be empty")
	}
}

func TestSetHeaderAllocatesMap(t *testing.T) {
	tok := &Token{}
	tok.SetHeader("kid", "abc")
	if tok.KeyID() != "abc" {
		t.Fatal("SetHeader did not allocate header map")
	}
}

func TestHeaderStringNilHeader(t *testing.T) {
	tok := &Token{}
	if tok.HeaderString("kid") != "" || tok.KeyID() != "" || tok.TokenType() != "" {
		t.Fatal("nil header accessors should return empty string")
	}
}
