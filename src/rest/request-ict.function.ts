import { FETCH_HTTP_REQUEST_FUNCTION, HttpRequestFunction } from './types/http-request-function.type';
import { ICTRequestOptions } from './types/ict-request-options.interface';
import { ICTResponse } from './types/ict-response.interface';

/**
 * Requests an Identity Certification Token.
 * @param options ICT Request Options.
 * @param http Optional HTTP Request function. Default is fetch.
 * @returns ICT Response containing the ICT.
 */
export async function requestIct(options: ICTRequestOptions, http: HttpRequestFunction = FETCH_HTTP_REQUEST_FUNCTION): Promise<ICTResponse> {
  // Request ICT.
  const result = await http('POST', options.ictEndpoint, new Headers({
    'Authorization': `bearer ${options.accessToken}`,
    'Content-Type': 'application/jwt+pop',
  }), options.popToken);

  // Return result or throw error.
  switch (result.responseCode) {
  case 201:
    return JSON.parse(result.body) as ICTResponse;
  case 401:
    throw new Error('Unauthorized to request an ICT');
  default:
    throw new Error('Failed to request ICT for unknown reasons');
  }
}
