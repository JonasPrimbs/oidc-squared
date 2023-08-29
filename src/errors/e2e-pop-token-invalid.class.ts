import * as jose from 'jose';

export class E2EPoPTokenInvalid extends jose.errors.JOSEError {
  constructor(message?: string | undefined) {
    super(message);
    this.code = 'ERR_E2E_POP_TOKEN_INVALID';
  }

  static override get code(): string {
    return 'ERR_E2E_POP_TOKEN_INVALID';
  }
}
