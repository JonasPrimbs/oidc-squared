import { IrtClaimSpecification } from './irt-claim-specification.interface';

export interface IrtClaimsSpecification {

  /**
   * Specification of a specific claim.
   * @default null
   */
  [claim: string]: null | IrtClaimSpecification;
}
