package jwt

// GetID returns the "jti" (JWT ID) claim, giving RegisteredClaims the same
// accessor MapClaims already exposes. It completes the registered-claim getter
// set for callers that treat claims uniformly.
func (c RegisteredClaims) GetID() string { return c.ID }

// UnregisterSigningMethod removes the signing method registered for alg, if any.
// After it returns, GetSigningMethod(alg) yields nil and the parser rejects
// tokens whose header names alg. It is the inverse of RegisterSigningMethod and
// is safe for concurrent use; unregistering an alg that is not present is a
// no-op. Use it to lock a process down to a curated set of algorithms.
func UnregisterSigningMethod(alg string) {
	signingMethodsMu.Lock()
	defer signingMethodsMu.Unlock()
	delete(signingMethods, alg)
}
