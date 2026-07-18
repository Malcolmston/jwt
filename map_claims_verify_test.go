package jwt

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestMapClaimsVerifyMethods(t *testing.T) {
	now := int64(1000)
	m := MapClaims{
		"iss": "issuer",
		"aud": []any{"a", "b"},
		"exp": float64(2000),
		"nbf": float64(500),
		"iat": float64(900),
	}

	cases := []struct {
		name string
		got  bool
		want bool
	}{
		{"aud-present", m.VerifyAudience("a", true), true},
		{"aud-missing-val", m.VerifyAudience("z", true), false},
		{"exp-not-expired", m.VerifyExpiresAt(now, true), true},
		{"exp-expired", m.VerifyExpiresAt(3000, true), false},
		{"iat-ok", m.VerifyIssuedAt(now, true), true},
		{"iat-future", m.VerifyIssuedAt(800, true), false},
		{"nbf-ok", m.VerifyNotBefore(now, true), true},
		{"nbf-early", m.VerifyNotBefore(400, true), false},
		{"iss-ok", m.VerifyIssuer("issuer", true), true},
		{"iss-bad", m.VerifyIssuer("other", true), false},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s: got %v want %v", tc.name, tc.got, tc.want)
		}
	}
}

func TestMapClaimsVerifyAbsentClaims(t *testing.T) {
	empty := MapClaims{}
	// req=false => absent passes; req=true => absent fails.
	if !empty.VerifyAudience("a", false) || empty.VerifyAudience("a", true) {
		t.Error("VerifyAudience absent handling wrong")
	}
	if !empty.VerifyExpiresAt(1, false) || empty.VerifyExpiresAt(1, true) {
		t.Error("VerifyExpiresAt absent handling wrong")
	}
	if !empty.VerifyIssuedAt(1, false) || empty.VerifyIssuedAt(1, true) {
		t.Error("VerifyIssuedAt absent handling wrong")
	}
	if !empty.VerifyNotBefore(1, false) || empty.VerifyNotBefore(1, true) {
		t.Error("VerifyNotBefore absent handling wrong")
	}
	if !empty.VerifyIssuer("x", false) || empty.VerifyIssuer("x", true) {
		t.Error("VerifyIssuer absent handling wrong")
	}
}

func TestMapClaimsTypedGetters(t *testing.T) {
	m := MapClaims{
		"count":  float64(42),
		"ratio":  float64(1.5),
		"admin":  true,
		"scopes": []any{"read", "write", 3},
		"single": "solo",
		"when":   float64(1600000000),
	}
	if v, ok := m.GetInt64("count"); !ok || v != 42 {
		t.Errorf("GetInt64 = %d, %v", v, ok)
	}
	if v, ok := m.GetFloat64("ratio"); !ok || v != 1.5 {
		t.Errorf("GetFloat64 = %f, %v", v, ok)
	}
	if v, ok := m.GetBool("admin"); !ok || !v {
		t.Errorf("GetBool = %v, %v", v, ok)
	}
	if got := m.GetStringSlice("scopes"); !reflect.DeepEqual(got, []string{"read", "write"}) {
		t.Errorf("GetStringSlice = %v", got)
	}
	if got := m.GetStringSlice("single"); !reflect.DeepEqual(got, []string{"solo"}) {
		t.Errorf("GetStringSlice single = %v", got)
	}
	if tm, ok := m.GetTime("when"); !ok || tm.Unix() != 1600000000 {
		t.Errorf("GetTime = %v, %v", tm, ok)
	}
	if _, ok := m.GetInt64("missing"); ok {
		t.Error("GetInt64 missing should be false")
	}
}

func TestMapClaimsGetInt64JSONNumber(t *testing.T) {
	var m MapClaims
	dec := json.NewDecoder(strings.NewReader(`{"n": 9007199254740993}`))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		t.Fatal(err)
	}
	// A value beyond float64's exact integer range must survive via json.Number.
	if v, ok := m.GetInt64("n"); !ok || v != 9007199254740993 {
		t.Errorf("GetInt64 json.Number = %d, %v", v, ok)
	}
}

func TestMapClaimsSetAndHas(t *testing.T) {
	m := MapClaims{}
	m.Set("a", 1).Set("b", "two")
	if !m.Has("a") || !m.Has("b") {
		t.Fatal("Set did not store values")
	}
	if m.Has("c") {
		t.Fatal("Has reported a missing key")
	}
	m["nilval"] = nil
	if m.Has("nilval") {
		t.Fatal("Has must treat nil as absent")
	}
}

func TestGetTimeUnix(t *testing.T) {
	m := MapClaims{"t": float64(0)}
	got, ok := m.GetTime("t")
	if !ok || !got.Equal(time.Unix(0, 0).UTC()) {
		t.Fatalf("GetTime epoch = %v, %v", got, ok)
	}
}

func BenchmarkMapClaimsVerifyExpiresAt(b *testing.B) {
	m := MapClaims{"exp": float64(2000)}
	for i := 0; i < b.N; i++ {
		_ = m.VerifyExpiresAt(1000, true)
	}
}
