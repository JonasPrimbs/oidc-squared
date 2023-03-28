export interface IrtClaimSpecification {

  /**
   * Indicates whether the requested claim is essential.
   * If set to true, the claim must be present and the ID Certification Token will not be issued if not available.
   * If set to false, the claim is voluntary and is present in the ID Certification Token if available.
   * @default false
   */
  essential?: boolean;

  /**
   * Requested value of the claim.
   * If the claim is essential and its value does not match the requested value, the ID Certification Token will not be issued.
   * If the claim is not essential and its value does not match the requested value, the claim will not be present in the issued ID Certification Token.
   */
  value?: unknown;

  /**
   * Set of requested value opportunities in order of preference.
   * If the claim is essential and its value matches none of the requested values, the ID Certification Token will not be issued.
   * If the claim is not essential and its value matches none of the requested values, the claim will not be present in the issued ID Certification Token.
   */
  values?: unknown[];
}
