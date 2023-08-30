export class OidcSquaredNotSupportedError extends Error {
  constructor() {
    super('OIDC² is not supported by the OpenID Provider');
  }
}
