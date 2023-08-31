# Proof-of-Possession Token Generation

```typescript
import { NonceGenerators, SignPoPToken } from 'oidc-squared';

// Create new PoP Token:
//   This automatically sets:
//     - a newly generated UUID as "jti" (JWT ID) Claim.
//     - the current unix timestamp as "iat" (Issued At) Claim.
//     - the current unix timestamp + 60 seconds (= 1 minute) as "exp" (Expiration) Claim.
const popToken = new SignPoPToken();

// Export the public key as a JSON Web Key (JWK) to insert it into the public key.
const publicJwk = await crypto.subtle.exportKey('jwk', clientKeyPair.publicKey)

// Sets all header parameters manually:
popToken.setProtectedHeader({
  typ: 'jwt+pop', // This MUST be set to "jwt+pop" to identify it as a PoP Token.
  alg: 'ES384',   // Insert the Client's signing algorithm here.
  jwk: publicJwk, // Set the Client's public JWK here.
});
// You can also set the public key by only setting the public key:
popToken.setPublicKey(
  'ES384',    // Insert the Client's signing algorithm here.
  publicJwk,  // Set the Client's public JWK here.
);

// Set the Issuer (typically the Client ID):
popToken.setIssuer('myclient');

// Set the Subject (typically the End-User's subject identifier):
popToken.setSubject('alice');

// Set the Audience (typically the OpenID Provider's issuer URL):
popToken.setAudience('https://op.example.com');

// Get now as unix timestamp with seconds-precision.
const now = Math.floor(Date.now() / 1000);

// Set Issued At to timestamp specified in variable `now`:
popToken.setIssuedAt(now);
// Set Issued At to now:
popToken.setIssuedAt();
// In both cases: If Expiration Claim was not yet specified, it will be set to "iat" + 60 seconds.

// (Optional) Set Not Before to timestamp specified in variable `now`:
popToken.setNotBefore(now);
// (Optional) Set Not Before to "iat", or now, if not provided:
popToken.setNotBefore();

// Set Expiration to specified timestamp.
popToken.setExpirationTime(now + 60);

// Set the JWT ID to a Universally Unique Identifier (UUID).
popToken.setJti();
// You can also set the JWT ID to an explicit Universally Unique Identifier (UUID).
popToken.setJti(NonceGenerators.uuid().generate());
// You can also set the JWT ID to a random n-bytes (here: 16 bytes) long Base64-encoded string.
popToken.setJti(NonceGenerators.base64(16).generate());

// Set the requested required claims for the ICT.
popToken.setRequiredClaims(['name']);

// Set the requested optional claims for the ICT.
popToken.setOptionalClaims(['email']);

// Sets whether the audience claim should be present in the ICT.
popToken.setWithAudience(true);
// If no boolean provided, the claim will be deleted and defaults to true.
popToken.setWithAudience();

// Signs the PoP Token using the provided private key and returns its token string.
const token = await popToken.sign(clientKeyPair.privateKey);
```
