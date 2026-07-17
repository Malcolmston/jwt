// Library content for the jwt documentation site. Mirrors the shape used by
// the malcolmston/go landing site's data.ts so the sibling sites stay in sync.
export interface Lib {
  id: string; name: string; icon: string; accent: string; pkg: string; node: string;
  repo: string; docs: string; tagline: string; blurb: string; tags: string[];
  features: string[]; node_code: string; go_code: string; integrate: string;
}

export const NODE_ACCENT = '#8cc84b';

export const JWT: Lib = {
  id:"jwt", name:"JWT", icon:'<i class="fa-solid fa-key"></i>', accent:"#fb015b",
  pkg:"github.com/malcolmston/jwt", node:"auth0/node-jsonwebtoken",
  repo:"https://github.com/malcolmston/jwt", docs:"https://malcolmston.github.io/jwt/",
  tagline:"Standard-library-only JSON Web Tokens for Go.",
  blurb:"A from-scratch Go implementation of JSON Web Tokens (RFC 7519) on top of the JWS compact "+
    "serialization (RFC 7515), built entirely on the Go standard library — no third-party modules, "+
    "no cgo, no require directives. You sign with either <code>NewWithClaims(...).SignedString</code> or "+
    "the one-shot <code>Sign</code> helper, and verify with <code>Parse</code> / <code>ParseWithClaims</code> "+
    "driven by a <code>Keyfunc</code> for key selection. Every algorithm — HMAC-SHA (HS256/384/512), RSA "+
    "PKCS1v15 (RS*), RSA-PSS (PS*), ECDSA (ES*) and an opt-in unsecured none — implements a common "+
    "SigningMethod interface. RegisteredClaims models the IANA claim set with NumericDate encoding and a "+
    "string-or-array audience, MapClaims handles arbitrary payloads, and parser options give you method "+
    "allow-lists, audience/issuer/subject checks, configurable leeway and an injectable clock. Errors are "+
    "wrapped sentinels you match with errors.Is. The import path is github.com/malcolmston/jwt.",
  tags:["RFC 7519","JWS RFC 7515","HS256/384/512","RS* / PS*","ES256/384/512","Keyfunc","RegisteredClaims","MapClaims","errors.Is","PEM keys","opt-in none","zero deps"],
  features:[
    "One-call signing — <code>Sign(claims, SigningMethodHS256, []byte(secret))</code>, or build explicitly with <code>NewWithClaims(method, claims).SignedString(key)</code>",
    "Verification through <code>Parse</code> (into <code>MapClaims</code>) and <code>ParseWithClaims</code> (into your own <code>Claims</code>), resolving keys via a <code>Keyfunc</code> that sees the header for <code>kid</code> selection",
    "Every algorithm behind one <code>SigningMethod</code> interface — HMAC <code>SigningMethodHS256/384/512</code>, RSA <code>RS*</code>, RSA-PSS <code>PS*</code>, ECDSA <code>ES*</code> (fixed-width r&#124;&#124;s), plus opt-in <code>none</code>",
    "<code>RegisteredClaims</code> covers iss, sub, aud, exp, nbf, iat, jti with <code>NumericDate</code> epoch-seconds and string-or-array <code>ClaimStrings</code> audience",
    "<code>MapClaims</code> for arbitrary payloads, or any custom struct satisfying the one-method <code>Claims</code> interface (embed <code>RegisteredClaims</code>)",
    "Parser options — <code>WithValidMethods</code> (defeat alg-confusion), <code>WithAudience</code>, <code>WithIssuer</code>, <code>WithSubject</code>, <code>WithLeeway</code>, <code>WithExpirationRequired</code>, <code>WithIssuedAt</code>",
    "Deterministic time — <code>WithClock</code> / <code>WithTimeFunc</code> and the <code>ClockFunc</code> adapter make exp/nbf/iat validation reproducible in tests",
    "PEM key helpers — <code>ParseRSAPrivateKeyFromPEM</code>, <code>ParseRSAPublicKeyFromPEM</code>, <code>ParseECPrivateKeyFromPEM</code>, <code>ParseECPublicKeyFromPEM</code> (PKCS#1/SEC1/PKCS#8/PKIX)",
    "Wrapped sentinel errors — <code>ErrTokenExpired</code>, <code>ErrSignatureInvalid</code>, <code>ErrTokenInvalidAudience</code>, <code>ErrTokenNotValidYet</code> and more, all matchable with <code>errors.Is</code>",
    "Double opt-in <code>none</code> — the parser needs <code>WithAllowNone</code> <i>and</i> the <code>UnsafeAllowNoneSignatureType</code> sentinel key, so unsecured tokens never slip through by default",
    "Base64url (no padding) header/payload/signature encoding, tag headers with <code>SetKID</code>, expose the signing input via <code>SigningString</code>",
    "Zero dependencies — pure Go standard library (crypto/*, encoding/*, math/big), no cgo, nothing to audit but the toolchain"
  ],
  node_code:
`const jwt = require("jsonwebtoken");

const token = jwt.sign(
  { sub: "user-42", aud: "api.example.com" },
  "my-hmac-secret",
  { algorithm: "HS256", issuer: "auth.example.com", expiresIn: "1h" }
);

const claims = jwt.verify(token, "my-hmac-secret", {
  algorithms: ["HS256"],       // reject algorithm confusion
  audience: "api.example.com",
  issuer: "auth.example.com",
});
console.log(claims.sub);`,
  go_code:
`import "github.com/malcolmston/jwt"

claims := jwt.RegisteredClaims{
    Issuer:    "auth.example.com",
    Subject:   "user-42",
    Audience:  jwt.ClaimStrings{"api.example.com"},
    ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
}
signed, _ := jwt.Sign(claims, jwt.SigningMethodHS256, []byte("my-hmac-secret"))

var out jwt.RegisteredClaims
tok, _ := jwt.ParseWithClaims(signed, &out,
    func(*jwt.Token) (any, error) { return []byte("my-hmac-secret"), nil },
    jwt.WithValidMethods([]string{"HS256"}), // reject algorithm confusion
    jwt.WithAudience("api.example.com"),
    jwt.WithIssuer("auth.example.com"))
fmt.Println(tok.Valid, out.Subject)`,
  integrate:
`<span class="tok-c">// Sign an RS256 token from a PEM private key, tagging the JOSE</span>
<span class="tok-c">// header with a key id so verifiers can select the right key.</span>
priv, _ := jwt.ParseRSAPrivateKeyFromPEM(privPEM)
signed, _ := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SetKID("2026-07").SignedString(priv)

<span class="tok-c">// Verify with a Keyfunc that picks the key by kid, and pin the</span>
<span class="tok-c">// accepted method so an attacker cannot downgrade the algorithm.</span>
pub, _ := jwt.ParseRSAPublicKeyFromPEM(pubPEM)
tok, err := jwt.Parse(signed, func(t *jwt.Token) (any, error) {
    if t.Header["kid"] != "2026-07" {
        return nil, jwt.ErrTokenUnverifiable
    }
    return pub, nil
}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithLeeway(30*time.Second))

<span class="tok-c">// Every parser failure is a wrapped sentinel — match it with errors.Is.</span>
if errors.Is(err, jwt.ErrTokenExpired) {
    <span class="tok-c">// prompt a refresh...</span>
}
fmt.Println(tok.Valid)`
};
