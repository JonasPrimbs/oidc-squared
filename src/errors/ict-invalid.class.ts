import * as jose from 'jose';

export class ICTInvalid extends jose.errors.JOSEError {
  constructor(message?: string | undefined) {
    super(message);
    this.code = 'ERR_ICT_INVALID';
  }

  static override get code(): string {
    return 'ERR_ICT_INVALID';
  }
}
