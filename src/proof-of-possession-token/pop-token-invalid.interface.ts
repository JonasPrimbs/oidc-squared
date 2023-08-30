import * as jose from 'jose';

export class PoPTokenInvalid extends jose.errors.JOSEError {
  constructor(message?: string | undefined) {
    super(message);
    this.code = 'ERR_POP_TOKEN_INVALID';
  }

  static override get code(): string {
    return 'ERR_POP_TOKEN_INVALID';
  }
}
