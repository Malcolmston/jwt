package jwt

import (
	"errors"
	"fmt"
	"time"
)

// Clock supplies the current time to the validator. Injecting a Clock makes
// exp/nbf/iat validation deterministic in tests.
type Clock interface {
	Now() time.Time
}

// ClockFunc adapts a function to the Clock interface.
type ClockFunc func() time.Time

// Now calls the wrapped function.
func (f ClockFunc) Now() time.Time { return f() }

// systemClock is the default Clock backed by time.Now.
type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

// validator applies time-based and equality-based validation to claims. It is
// configured through parser options.
type validator struct {
	clock              Clock
	leeway             time.Duration
	verifyIAT          bool
	expectedAud        string
	expectedIss        string
	expectedSub        string
	expirationRequired bool
	maxTokenAge        time.Duration
	ignoreExp          bool
	ignoreNbf          bool
}

func newValidator() *validator {
	return &validator{clock: systemClock{}}
}

// Validate runs all configured checks against c. All applicable errors are
// joined so a caller can test the returned error for any of them with
// errors.Is.
func (v *validator) Validate(c claimsGetter) error {
	now := v.clock.Now()
	var errs []error

	if !v.ignoreExp {
		if exp := c.GetExpirationTime(); exp != nil {
			if !now.Before(exp.Add(v.leeway)) {
				errs = append(errs, fmt.Errorf("%w: expired at %v", ErrTokenExpired, exp.Time))
			}
		} else if v.expirationRequired {
			errs = append(errs, fmt.Errorf("%w: exp", ErrTokenRequiredClaimMissing))
		}
	}

	if !v.ignoreNbf {
		if nbf := c.GetNotBefore(); nbf != nil {
			if now.Add(v.leeway).Before(nbf.Time) {
				errs = append(errs, fmt.Errorf("%w: not before %v", ErrTokenNotValidYet, nbf.Time))
			}
		}
	}

	if v.verifyIAT {
		if iat := c.GetIssuedAt(); iat != nil {
			if now.Add(v.leeway).Before(iat.Time) {
				errs = append(errs, fmt.Errorf("%w: issued at %v", ErrTokenUsedBeforeIssued, iat.Time))
			}
		}
	}

	// max-token-age: reject tokens whose age (now - iat) exceeds the bound.
	// The iat claim is required for this check, mirroring node jsonwebtoken's
	// maxAge behavior.
	if v.maxTokenAge > 0 {
		iat := c.GetIssuedAt()
		if iat == nil {
			errs = append(errs, fmt.Errorf("%w: iat (required by max-token-age)", ErrTokenRequiredClaimMissing))
		} else if now.Sub(iat.Time) > v.maxTokenAge+v.leeway {
			errs = append(errs, fmt.Errorf("%w: age %v exceeds %v", ErrTokenTooOld, now.Sub(iat.Time), v.maxTokenAge))
		}
	}

	if v.expectedAud != "" {
		if err := verifyAud(c.GetAudience(), v.expectedAud); err != nil {
			errs = append(errs, err)
		}
	}

	if v.expectedIss != "" && c.GetIssuer() != v.expectedIss {
		errs = append(errs, fmt.Errorf("%w: got %q want %q", ErrTokenInvalidIssuer, c.GetIssuer(), v.expectedIss))
	}

	if v.expectedSub != "" && c.GetSubject() != v.expectedSub {
		errs = append(errs, fmt.Errorf("%w: got %q want %q", ErrTokenInvalidSubject, c.GetSubject(), v.expectedSub))
	}

	if len(errs) == 0 {
		return nil
	}
	return errors.Join(errs...)
}

// verifyAud reports whether aud contains the expected audience.
func verifyAud(aud ClaimStrings, expected string) error {
	for _, a := range aud {
		if a == expected {
			return nil
		}
	}
	return fmt.Errorf("%w: %q not in %v", ErrTokenInvalidAudience, expected, []string(aud))
}
