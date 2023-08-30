# Identity Certification Token Generation

```typescript
import { SignICT } from 'oidc-squared';

// Create new ICT:
//   This automatically sets:
//     - a newly generated UUID as "jti" (JWT ID) Claim.
//     - the current unix timestamp as "iat" (Issued At) Claim.
//     - the current unix timestamp + 300 seconds (= 5 minutes) as "exp" (Expiration) Claim.
const ict = new SignICT();

// Sets all header parameters manually:
ict.setProtectedHeader({
  typ: 'jwt+ict', // This MUST be set to "jwt+ict" to identify it as an ICT.
  alg: 'RS384',   // Insert the OpenID Provider's signing algorithm here.
  kid: 'key#1',   // Insert the Key ID from the JWKS Endpoint here.
});
// You can also set the public key by only setting the Key ID:
ict.setKeyId(
  'RS384',  // Insert the OpenID Provider's signing algorithm here.
  'key#1',  // Insert the Key ID from the JWKS Endpoint here.
);

// Set the Issuer (typically the OpenID Provider's issuer URL):
ict.setIssuer('https://op.example.com');

// Set the Subject (typically the End-User's subject identifier):
ict.setSubject('alice');

// (Optional) Set the Audience (typically the Client ID):
ict.setAudience('myclient'); // optional

// Get now as unix timestamp with seconds-precision.
const now = Math.floor(Date.now() / 1000);

// Set Issued At to timestamp specified in variable `now`.
ict.setIssuedAt(now);
// Set Issued At to now:
ict.setIssuedAt();
// In both cases: If Expiration Claim was not yet specified, it will be set to "iat" + 300 seconds.

// (Optional) Set Not Before to timestamp specified in variable `now`:
ict.setNotBefore(now);
// (Optional) Set Not Before to "iat", or now, if not provided:
ict.setNotBefore();

// Set Expiration to specified timestamp.
ict.setExpirationTime(now + 300);

// Set the JWT ID to a Universally Unique Identifier (UUID).
ict.setJti();
// You can also set the JWT ID to an explicit Universally Unique Identifier (UUID).
ict.setJti(NonceGenerators.uuid().generate());
// You can also set the JWT ID to a random n-bytes (here: 16 bytes) long Base64-encoded string.
ict.setJti(NonceGenerators.base64(16).generate());

// Set the Client's Public Key to the "cnf" (Confirmation) Claim.
ict.setConfirmation(popResult.protectedHeader.jwk);

// Set all the granted end-to-end authentication contexts.
ict.setContext(['example-app-1', 'example-app-2']);
// If there is only one granted context, you can also use a string.
ict.setContext('example-app');

// Signs the ICT using the provided private key and returns its token string.
const token = await ict.sign(opKeyPair.privateKey);
```
