export interface JwtVerificationOptions {

  /**
   * Enables (true) / disables (false) to verify the signature.
   * @default true
   */
  verifySignature: boolean;

  /**
   * Enables / disables to verify the time validity.
   * @default true
   */
  verifyTime: boolean;

  /**
   * Sets the unix timestamp with seconds precision or Date when to verify the validity.
   * @default Date.now()
   */
  verificationTime: Date | number;

  /**
   * Maximum allowed time shift.
   * @defalt 0
   */
  verificationTimeDelta: number;
}
