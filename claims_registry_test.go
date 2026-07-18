package jwt

import "testing"

func TestRegisteredClaimsGetID(t *testing.T) {
	c := RegisteredClaims{ID: "jti-123"}
	if c.GetID() != "jti-123" {
		t.Fatalf("GetID = %q", c.GetID())
	}
}

func TestUnregisterSigningMethod(t *testing.T) {
	const alg = "TESTALG-XYZ"
	if GetSigningMethod(alg) != nil {
		t.Fatal("test alg should not be pre-registered")
	}
	RegisterSigningMethod(alg, func() SigningMethod { return SigningMethodNoneAlg })
	if GetSigningMethod(alg) == nil {
		t.Fatal("RegisterSigningMethod did not take effect")
	}
	UnregisterSigningMethod(alg)
	if GetSigningMethod(alg) != nil {
		t.Fatal("UnregisterSigningMethod did not remove the method")
	}
	// Unregistering an absent alg is a no-op.
	UnregisterSigningMethod(alg)
}
