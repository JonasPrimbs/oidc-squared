import * as crypto from 'crypto';
import { encodeBase64url } from '@jonasprimbs/byte-array-converter';

import { IctRequestTokenHeader } from './ict-request-token-header.interface';
import { IctRequestTokenPayload } from './ict-request-token-payload.interface';
import { IrtClaimSpecification } from './irt-claim-specification.interface';
import { IrtClaimsSpecification } from './irt-claims-specification.interface';
import { NonceGenerators } from '../nonce-generators';
import { JwsSignatureAlgorithm } from '../types';

export class IctRequestToken {

  /**
   * The public key to prove possession of.
   */
  private publicKey?: crypto.webcrypto.CryptoKey;

  /**
   * The signature.
   */
  private signature?: Uint8Array;

  /**
   * The claims of the payload.
   */
  private readonly claims: Partial<IctRequestTokenPayload> = {};

  /**
   * Sets the public key for the ICT Request Token.
   * @param publicKey Public key of the ICT Request Token.
   * @returns The updated ICT Request Token instance.
   */
  setPublicKey(publicKey: crypto.webcrypto.CryptoKey): IctRequestToken {
    // Verify that provided key is a public key.
    if (publicKey.type !== 'public') {
      throw new Error('Provided public key is not of type "public"!');
    }
    // Verify that provided key is meant for signing.
    if (publicKey.usages.indexOf('verify') === -1) {
      throw new Error('Provided public key has no usage "verify"!');
    }
    // Verify that provided key is extractable.
    if (!publicKey.extractable) {
      throw new Error('Provided public key is not extactable!');
    }
    // Verify that provided key has a sufficient algorithm name.
    switch (publicKey.algorithm.name) {
    case 'ECDSA':
      // ES256 / ES384 / ES512.
      break;
    case 'RSA-PSS':
      // PS256 / PS384 / PS512.
      break;
    case 'RSASSA-PKCS1-v1_5':
      // RS256 / RS384 / RS512.
      break;
    default:
      throw new Error(`Provided public key has an unsupported signing algorithm "${publicKey.algorithm.name}"!`);
    }

    // Clear outdated signature.
    this.signature = undefined;

    // Set public key.
    this.publicKey = publicKey;

    return this;
  }

  /**
   * Indicates whether a public key is provided.
   * @returns true = has a public key; false = has no public key.
   */
  hasPublicKey(): boolean {
    return this.publicKey instanceof crypto.webcrypto.CryptoKey;
  }

  /**
   * Gets the set public key.
   * @returns The public key.
   */
  getPublicKey(): crypto.webcrypto.CryptoKey | undefined {
    return this.publicKey;
  }

  /**
   * Exports the public key.
   * @param format Format of the exported public key.
   * @returns The exported public key.
   */
  async exportPublicKey<T extends KeyExportFormat>(format: T): Promise<KeyExportType<T> | undefined> {
    if (this.publicKey === undefined) {
      return undefined;
    }

    if (format === 'jwk') {
      return await crypto.subtle.exportKey(format, this.publicKey) as KeyExportType<T>;
    } else {
      return await crypto.subtle.exportKey(format, this.publicKey) as KeyExportType<T>;
    }
  }

  /**
   * Sets the "sub" (Subject) claim.
   * @param subject Subject of the ICT Request Token, e.g., the user's identifier ("sub" claim in the ID Token).
   * @returns The updated ICT Request Token instance.
   */
  setSubject(subject: string): IctRequestToken {
    // Validate subject.
    if (!isStringOrUri(subject)) {
      throw new Error(`Invalid subject "${subject}"! Must be a valid URL since it contains a ':' character!`);
    }
    // Verify that subject is not empty.
    if (subject === '') {
      return this;
    }

    // Clear outdated signature.
    this.signature = undefined;

    // Set the subject ("sub") claim.
    this.claims.sub = subject;

    return this;
  }

  /**
   * Indicates whether the subject is provided.
   * @returns true = has subject; false = has no subject.
   */
  hasSubject(): boolean {
    return !!this.claims.sub;
  }

  /**
   * Gets the subject of the ICT Request Token.
   * @returns The provided subject.
   */
  getSubject(): string | undefined {
    return this.claims.sub;
  }

  /**
   * Sets the "aud" (Audience) claim.
   * @param audience Audience(s) of the ICT Request Token, e.g., the OpenID Provider's identifier ("iss" claim in the ID Token).
   * @returns The updated ICT Request Token instance.
   */
  setAudience(audience: string | string[]): IctRequestToken {
    // Convert input audience to string array.
    const audArray = typeof audience === 'string' ? [ audience ] : [ ...audience ];
    // Filter all insufficient audience values and duplicates from array.
    const filteredAud = [...new Set(audArray.filter(a => a !== ''))];

    // Do not change the audience if no sufficient audience is provided.
    if (filteredAud.length === 0) {
      return this;
    }

    // Verify validity of provided audiences.
    const errorIndex = filteredAud.findIndex(a => !isStringOrUri(a));
    // Throw error if any audience is invalid.
    if (errorIndex >= 0) {
      throw new Error(`Invalid audience "${audience[errorIndex]}"! Must be a valid URL since it contains a ':' character!`);
    }

    // Clear outdated signature.
    this.signature = undefined;

    // Set audience claim.
    if (filteredAud.length === 1) {
      this.claims.aud = filteredAud[0];
    } else {
      this.claims.aud = filteredAud;
    }

    return this;
  }

  /**
   * Indicates whether the audience is provided.
   * @returns true = has an audience; false = has no audience.
   */
  hasAudience(): boolean {
    if (!this.claims.aud) {
      return false;
    } else if (this.claims.aud instanceof Array) {
      return this.claims.aud.length > 0;
    } else {
      return !!this.claims.aud;
    }
  }

  /**
   * Gets the audience of the ICT Request Token.
   * @returns The provided audience.
   */
  getAudience(): string[] | undefined {
    if (this.claims.aud === undefined) {
      return undefined;
    } else if (typeof this.claims.aud === 'string') {
      return [ this.claims.aud ];
    } else {
      return [ ...this.claims.aud ];
    }
  }

  /**
   * Gets whether the ICT Request Token contains a specific audience.
   * @param audience Audience to search for.
   * @returns true = contains audience; false = does not contain audience.
   */
  containsAudience(audience: string): boolean {
    const aud = this.getAudience();
    if (aud === undefined) {
      return false;
    } else {
      return aud.indexOf(audience) >= 0;
    }
  }

  /**
   * Sets the "iss" (Issuer) claim.
   * @param issuer Issuer of the ICT Request Token, e.g., the Client's identifier ("aud" claim in the ID Token).
   * @returns The updated ICT Request Token instance.
   */
  setIssuer(issuer: string): IctRequestToken {
    // Validate issuer.
    if (!isStringOrUri(issuer)) {
      throw new Error(`Invalid issuer "${issuer}"! Must be a valid URL since it contains a ':' character!`);
    }
    // Verify that issuer is not empty.
    if (issuer === '') {
      return this;
    }

    // Clear outdated signature.
    this.signature = undefined;

    // Set the issuer ("iss") claim.
    this.claims.iss = issuer;

    return this;
  }

  /**
   * Indicates whether the issuer is provided.
   * @returns true = has an issuer; false = has no issuer.
   */
  hasIssuer(): boolean {
    return !!this.claims.iss;
  }

  /**
   * Gets the issuer of the ICT Request Token.
   * @returns The provided issuer.
   */
  getIssuer(): string | undefined {
    return this.claims.iss;
  }

  /**
   * Sets the "jti" (JSON Web Token ID) claim.
   * @param jwtId JSON Web Token ID of the ICT Request Token. Typically a registered random string. If not provided, a random UUID will be generated.
   * @returns The updated ICT Request Token instance.
   */
  setJti(jwtId: string = NonceGenerators.uuid().generate()): IctRequestToken {
    // Validate provided JWT Token ID.
    if (jwtId === '') {
      throw new Error('Invalid JWT Token ID (jti): Must be a unique string!');
    }

    // Clear outdated signature.
    this.signature = undefined;

    // Set the JWT ID ("jti") claim.
    this.claims.jti = jwtId;

    return this;
  }

  /**
   * Indicates whether a JWT ID is provided.
   * @returns true = has a JWT ID; false = has no JWT ID.
   */
  hasJti(): boolean {
    return !!this.claims.jti;
  }

  /**
   * Gets the JWT ID of the ICT Request Token.
   * @returns The provided JWT ID.
   */
  getJti(): string | undefined {
    return this.claims.jti;
  }

  /**
   * Sets the "nonce" (Nonce) claim.
   * @param nonce Nonce of the ICT Request Token. Typically a random string. If not provided, a random 15 bytes long base64 string will be generated.
   * @returns The updated ICT Request Token instance.
   */
  setNonce(nonce: string = NonceGenerators.base64(15).generate()): IctRequestToken {
    // Validate input value.
    if (!nonce) {
      throw new Error('Nonce value must not be an empty string!');
    }

    // Clear outdated signature.
    this.signature = undefined;

    // Set the Nonce ("nonce") claim.
    this.claims.nonce = nonce;

    return this;
  }

  /**
   * Indicates whether the nonce is provided.
   * @returns true = has a nonce; false = has no nonce.
   */
  hasNonce(): boolean {
    return !!this.claims.nonce;
  }

  /**
   * Gets the nonce of the ICT Request Token.
   * @returns The provided nonce.
   */
  getNonce(): string | undefined {
    return this.claims.nonce;
  }

  /**
   * Sets the "iat" (Issued at) claim.
   * @param issuedAt Issued at time as Date or as numbered unix timestamp with seconds precision. Default is current timestamp.
   * @returns The updated ICT Request Token instance.
   */
  setIssuedAt(issuedAt?: number | Date): IctRequestToken {
    if (issuedAt instanceof Date) {
      // Set UTC unix timestamp to issued at time.
      this.claims.iat = issuedAt.getTime() / 1000;
    } else if (typeof issuedAt === 'number') {
      // Validate timestamp.
      if (!isTimestamp(issuedAt)) {
        throw new Error(`Invalid timestamp ${issuedAt}!`);
      }
      // Set provided UTC unix timestamp to issued at time.
      this.claims.iat = issuedAt;
    } else {
      // Set current UTX unix timestamp to issued at time.
      this.claims.iat = Math.floor(Date.now() / 1000);
    }

    // Clear outdated signature.
    this.signature = undefined;

    return this;
  }

  /**
   * Indicates whether the issued at time is provided.
   * @returns true = has an issued at time; false = has no issued at time.
   */
  hasIssuedAt(): boolean {
    return !!this.claims.iat;
  }

  /**
   * Gets the issued at time of the ICT Request Token as unix timestamp with seconds precision.
   * @returns The provided issued at time as unix timestamp with seconds precision.
   */
  getIssuedAt(): number | undefined {
    return this.claims.iat;
  }

  /**
   * Gets the issued at time of the ICT Request Token as a date object.
   * @returns The provided issued at time as date object.
   */
  getIssuedAtDate(): Date | undefined {
    if (!this.claims.iat) {
      return undefined;
    } else {
      return new Date(this.claims.iat * 1000);
    }
  }

  /**
   * Sets the "nbf" (Not before) claim.
   * @param notBefore Not before time as Date or as numbered unix timestamp with second precision. Default is issued at time if defined, otherwise current timestamp.
   * @returns The updated ICT Request Token instance.
   */
  setNotBefore(notBefore?: number | Date): IctRequestToken {
    if (notBefore instanceof Date) {
      // Set UTC unix timestamp to not before time.
      this.claims.nbf = notBefore.getTime() / 1000;
    } else if (typeof notBefore === 'number') {
      // Validate timestamp.
      if (!isTimestamp(notBefore)) {
        throw new Error(`Invalid timestamp ${notBefore}!`);
      }
      // Set provided UTC unix timestamp to not before time.
      this.claims.nbf = notBefore;
    } else {
      // Set issued at date if defined, otherwise current unix timestamp with seconds precision.
      this.claims.nbf = this.getIssuedAt() ?? Math.round(Date.now() / 1000);
    }

    // Clear outdated signature.
    this.signature = undefined;

    return this;
  }

  /**
   * Indicates whether the not before time is provided.
   * @returns true = has a not before time; false = has no not before time.
   */
  hasNotBefore(): boolean {
    return !!this.claims.nbf;
  }

  /**
   * Gets the not before time of the ICT Request Token as unix timestamp with seconds precision.
   * @returns The provided not before time as unix timestamp with seconds precision.
   */
  getNotBefore(): number | undefined {
    return this.claims.nbf;
  }

  /**
   * Gets the not before time of the ICT Request Token as a date object.
   * @returns The provided not before time as date object.
   */
  getNotBeforeDate(): Date | undefined {
    if (!this.claims.nbf) {
      return undefined;
    } else {
      return new Date(this.claims.nbf * 1000);
    }
  }

  /**
   * Sets the "exp" (Expiration time) claim.
   * @param expirationTime Expiration time as Date or as numbered unix timestamp with second precision.
   * @returns The updated ICT Request Token instance.
   */
  setExpirationTime(expirationTime: number | Date): IctRequestToken {
    if (expirationTime instanceof Date) {
      // Set UTC unix timestamp to expiration time.
      this.claims.exp = expirationTime.getTime() / 1000;
    } else {
      // Validate timestamp.
      if (!isTimestamp(expirationTime)) {
        throw new Error(`Invalid timestamp ${expirationTime}!`);
      }
      // Set provided UTC unix timestamp to expiration time.
      this.claims.exp = expirationTime;
    }

    // Clear outdated signature.
    this.signature = undefined;

    return this;
  }

  /**
   * Indicates whether the expiration time is provided.
   * @returns true = has an expiration time; false = has no expiration time.
   */
  hasExpirationTime(): boolean {
    return !!this.claims.exp;
  }

  /**
   * Gets the expiration time of the ICT Request Token as unix timestamp with seconds precision.
   * @returns The provided expiration time as unix timestamp with seconds precision.
   */
  getExpirationTime(): number | undefined {
    return this.claims.exp;
  }

  /**
   * Gets the expiration time of the ICT Request Token as a date object.
   * @returns The provided expiration time as date object.
   */
  getExpirationTimeDate(): Date | undefined {
    if (!this.claims.exp) {
      return undefined;
    } else {
      return new Date(this.claims.exp * 1000);
    }
  }

  /**
   * Sets the "token_claims" (desired identity claims for the ID Certification Token) claim.
   * @param claims Enumeration of desired identity claims for the requested ID Certification Token. Duplicates and empty strings will be omitted. If no claim is provided, the call will be ignored.
   * @returns The updated ICT Request Token instance.
   */
  setTokenClaims(claims: IrtClaimsSpecification): IctRequestToken {
    // Verify that length is not empty.
    if (Object.keys(claims).length === 0) {
      return this;
    }

    // Create new instance of the claims specification.
    const claimsSpecification: IrtClaimsSpecification = {};

    // Validate claims.
    for (const claimName in claims) {
      // Get claim value.
      const claimValue = claims[claimName];

      // Copy claim value if null.
      if (claimValue === null) {
        claimsSpecification[claimName] = null;
        continue;
      }

      // Create a new ID Certification Request Token claim specification.
      const claimSpecification: IrtClaimSpecification = {
        essential: claimValue.essential === true,
      };

      // Validate desired values.
      if (claimValue.values !== undefined) {
        // Verify that value and values is not defined both.
        if (claimValue.value !== undefined) {
          throw new Error('Either "value", "values", or both must not be defined!');
        }

        // Filter all irrelevant values.
        const filteredValues = [...new Set(claimValue.values.filter(v => v !== '' && v !== undefined)) ];

        if (filteredValues.length === 1) {
          // Make 'values' array with one value to the 'value' attribute. 
          claimSpecification.value = JSON.parse(JSON.stringify(filteredValues[0]));
        } else if (filteredValues.length > 0) {
          // Copy remaining values into new values array.
          claimSpecification.values = [];
          for (const value of filteredValues) {
            claimSpecification.values.push(JSON.parse(JSON.stringify(value)));
          }
        }
      } else if (claimValue.value !== undefined) {
        // Copy 'value' attribute if sufficient.
        claimSpecification.value = JSON.parse(JSON.stringify(claimValue.value));
      }

      // Make created claim specification the new specification of the current claim.
      claimsSpecification[claimName] = claimSpecification;
    }

    // Clear outdated signature.
    this.signature = undefined;

    // Set the token claims ("token_claims") value.
    this.claims.token_claims = claimsSpecification;

    return this;
  }

  /**
   * Indicates whether the token claims are provided.
   * @returns true = has token claims; false = has no token claims.
   */
  hasTokenClaims(): boolean {
    return !!this.claims.token_claims;
  }

  /**
   * Gets the token claims of the ICT Request Token.
   * @returns The provided token claims.
   */
  getTokenClaims(): IrtClaimsSpecification | undefined {
    if (this.claims.token_claims === undefined) {
      return undefined;
    }

    // Return a deep copy of the set token claims.
    return JSON.parse(JSON.stringify(this.claims.token_claims));
  }

  /**
   * Gets the ICT Request Token header as object.
   * @returns The ICT Request Token header as object.
   */
  async getHeaderObject(): Promise<IctRequestTokenHeader> {
    const publicKey = this.publicKey;
    if (!publicKey) {
      throw new Error('Public key missing!');
    }

    const key = await crypto.subtle.exportKey('jwk', publicKey);

    return {
      typ: 'JWT+IRT',
      alg: getSufficientSignatureAlgorithm(publicKey),
      jwk: key,
    };
  }

  /**
   * Gets the ICT Request Token header as JSON-serialized and Base64URL encoded string.
   * @returns The ICT Request Token header as JSON-serialized and Base64URL encoded string.
   */
  async getHeaderString(): Promise<string> {
    const obj = await this.getHeaderObject();
    return objectToBase64Url(obj);
  }

  /**
   * Gets the ICT Request Token payload as object.
   * @returns The ICT Request Token payload as object.
   */
  getPayloadObject(): IctRequestTokenPayload {
    // Verify that issuer is set.
    if (!this.claims.iss) {
      throw new Error('No issuer set!');
    }
    // Verify that subject is set.
    if (!this.claims.sub) {
      throw new Error('No subject set!');
    }
    // Verify that audience is set.
    if (!this.claims.aud) {
      throw new Error('No audience set!');
    }
    // Verify that date is set.
    if (!this.claims.iat) {
      throw new Error('No issued at date set!');
    }
    // Verify that expiration date is set.
    if (!this.claims.exp) {
      throw new Error('No expiration date set!');
    }

    // Return payload.
    return {
      iss: this.claims.iss,
      sub: this.claims.sub,
      aud: this.claims.aud,
      iat: this.claims.iat,
      nbf: this.claims.nbf,
      exp: this.claims.exp,
      jti: this.claims.jti,
      nonce: this.claims.nonce,
      token_claims: this.claims.token_claims,
    };
  }

  /**
   * Gets the ICT Request Token payload as JSON-serialized and Base64URL encoded string.
   * @returns The ICT Request Token payload as JSON-serialized and Base64URL encoded string.
   */
  getPayloadString(): string {
    const obj = this.getPayloadObject();
    return objectToBase64Url(obj);
  }

  /**
   * Gets the ICT Request Token header and payload, dot-separated as JSON-serialized and Base64URL encoded string.
   * @returns The ICT Request Token header and payload, dot-separated as JSON-serialized and Base64URL encoded string.
   */
  async getHeaderAndPayloadString(): Promise<string> {
    const header = await this.getHeaderString();
    const payload = this.getPayloadString();
    return `${header}.${payload}`;
  }

  async getHeaderAndPayloadBytes(): Promise<Uint8Array> {
    // Generate header and payload string.
    const headerAndPayloadString = await this.getHeaderAndPayloadString();

    // Convert string to ASCII encoded bytes.
    const asciiBytes = [];
    for (let i = 0; i < headerAndPayloadString.length; i++) {
      asciiBytes[i] = headerAndPayloadString.charCodeAt(i);
    }

    return new Uint8Array(asciiBytes);
  }

  /**
   * Signs an ICT Request Token.
   * @param privateKey The private key to sign the ICT Request Token with.
   * @returns Signed ICT Request Token.
   */
  async sign(privateKey: crypto.webcrypto.CryptoKey): Promise<IctRequestToken> {
    // Verify that provided key is a public key.
    if (privateKey.type !== 'private') {
      throw new Error('Provided private key is not of type "private"!');
    }
    // Verify that provided key is meant for signing.
    if (privateKey.usages.indexOf('sign') === -1) {
      throw new Error('Provided private key has no usage "sign"!');
    }
    // Verify that the public key is provided.
    if (!this.publicKey) {
      throw new Error('No public key provided!');
    }
    // Verify that provided key has a sufficient algorithm name.
    if (privateKey.algorithm.name !== this.publicKey.algorithm.name) {
      throw new Error(`Provided private key signing algorithm "${privateKey.algorithm.name}" does not match the set public key signing algorithm "${this.publicKey.algorithm.name}"!`);
    }

    // Generate header and payload as ASCII encoded byte string.
    const dataBuffer = await this.getHeaderAndPayloadBytes();

    // Sign the ASCII encoded bytes.
    const arrayBuffer = await crypto.webcrypto.subtle.sign(privateKey.algorithm.name, privateKey, dataBuffer);
    this.signature = new Uint8Array(arrayBuffer);

    return this;
  }

  /**
   * Gets the signature as Base64URL encoded string.
   * @returns The signature as Base64URL encoded string.
   */
  getSignatureString(): string {
    if (!this.signature) {
      throw new Error('Token not signed!');
    }

    return encodeBase64url(this.signature);
  }

  /**
   * Gets the ICT Request Token as JWT string.
   * @returns The ICT Request Token as JWT string.
   */
  async getTokenString(): Promise<string> {
    if (!this.signature) {
      throw new Error('Token not signed!');
    }

    // Generate header and payload string to sign.
    const headerAndPayloadString = await this.getHeaderAndPayloadString();

    return `${headerAndPayloadString}.${this.signature}`;
  }
}

/**
 * Output format of an exported key.
 */
export type KeyExportFormat = 'jwk' | 'pkcs8' | 'raw' | 'spki';

/**
 * The data type of an exported key depending on the key export format.
 */
export type KeyExportType<T extends KeyExportFormat> = T extends 'jwk' ? crypto.webcrypto.JsonWebKey : ArrayBuffer;

/**
 * Converts a string to an UTF8-encoded byte array.
 * @param str String to convert.
 * @returns The UTF8-encoded string.
 */
function stringToUtf8Array(str: string): Uint8Array {
  const encoder = new TextEncoder();
  return encoder.encode(str);
}

/**
 * Serializes an object with JSON and encodes the string Base64URL.
 * @param obj Object to convert.
 * @returns JSON-serialized and Base64URL encoded object as string.
 */
function objectToBase64Url(obj: object): string {
  const json = JSON.stringify(obj);
  const utf8 = stringToUtf8Array(json);
  return encodeBase64url(utf8);
}

/**
 * Gets a sufficient signing algorithm for a provided asymmetric key.
 * @param key An asymmetric key.
 * @returns A sufficient signing algorithm.
 */
function getSufficientSignatureAlgorithm(key: crypto.webcrypto.CryptoKey): JwsSignatureAlgorithm {
  switch (key.algorithm.name) {
  // Elliptic Curve: (ES256 / ES384 / ES512)
  case 'ECDSA': {
    const esAlgorithm = key.algorithm as crypto.webcrypto.EcKeyAlgorithm;
    switch (esAlgorithm.namedCurve) {
    case 'P-256':
      return 'ES256';
    case 'P-384':
      return 'ES384';
    case 'P-521':
      return 'ES512';
    default:
      throw new Error(`Unsupported curve name ${esAlgorithm.namedCurve}`);
    }
  }
  // RSA Probablistic Signing Scheme: (PS256 / PS384 / PS512)
  case 'RSA-PSS': {
    const psAlgorithm = key.algorithm as crypto.webcrypto.RsaHashedKeyAlgorithm;
    switch (psAlgorithm.hash.name) {
    case 'SHA-256':
      return 'RS256';
    case 'SHA-384':
      return 'RS384';
    case 'SHA-512':
      return 'RS512';
    default:
      throw new Error(`Unsupported hash algorithm name ${psAlgorithm.hash}`);
    }
  }
  // RSA Public Key Cryptography Standard: (RS256 / RS384 / RS512)
  case 'RSASSA-PKCS-v1_5': {
    const rsAlgorithm = key.algorithm as crypto.webcrypto.RsaHashedKeyAlgorithm;
    switch (rsAlgorithm.hash.name) {
    case 'SHA-256':
      return 'RS256';
    case 'SHA-384':
      return 'RS384';
    case 'SHA-512':
      return 'RS512';
    default:
      throw new Error(`Unsupported hash algorithm name ${rsAlgorithm.hash}`);
    }
  }
  default:
    throw new Error(`Unsupported algorithm name ${key.algorithm.name}`);
  }
}

/**
 * Validates a string to be a StringOrUri.
 * @param str String to validate.
 * @returns true = valid StringOrUri; false = no valid StringOrUri.
 */
function isStringOrUri(str: string): boolean {
  if (str.indexOf(':') >= 0) {
    try {
      new URL(str);
    } catch (error) {
      return false;
    }
  }
  return true;
}

function isTimestamp(timestamp: number): boolean {
  return timestamp >= 0 && Number.isFinite(timestamp);
}
