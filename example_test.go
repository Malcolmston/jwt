package jwt_test

import (
	"fmt"
	"time"

	"github.com/malcolmston/jwt"
)

// Example signs a token with HS256 and then parses and verifies it, printing a
// claim from the verified payload.
func Example() {
	secret := []byte("my-hmac-secret")

	// Use a fixed clock so the example is deterministic.
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	claims := jwt.RegisteredClaims{
		Issuer:    "auth.example.com",
		Subject:   "user-42",
		Audience:  jwt.ClaimStrings{"api.example.com"},
		ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		IssuedAt:  jwt.NewNumericDate(now),
	}

	signed, err := jwt.Sign(claims, jwt.SigningMethodHS256, secret)
	if err != nil {
		panic(err)
	}

	var parsed jwt.RegisteredClaims
	token, err := jwt.ParseWithClaims(signed, &parsed,
		func(t *jwt.Token) (any, error) { return secret, nil },
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithClock(jwt.ClockFunc(func() time.Time { return now })),
		jwt.WithAudience("api.example.com"),
		jwt.WithIssuer("auth.example.com"),
	)
	if err != nil {
		panic(err)
	}

	fmt.Println("valid:", token.Valid)
	fmt.Println("subject:", parsed.Subject)

	// Output:
	// valid: true
	// subject: user-42
}
