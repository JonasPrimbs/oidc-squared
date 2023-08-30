import { OidcSquaredNotSupportedError } from '../errors/oidc-squared-not-supported-error.class';
import { FETCH_HTTP_REQUEST_FUNCTION, HttpRequestFunction } from './types/http-request-function.type';

function getDiscoveryUrl(opBaseUrl: string): string {
  const opUrl = new URL(opBaseUrl);
  return `${opUrl.origin}${opUrl.pathname.endsWith('/') ? opUrl.pathname : `${opUrl.pathname}/`}.well-known/openid-configuration`;
}

async function requestDiscoveryDocument(discoveryUrl: string, http: HttpRequestFunction) {
  const result = await http('GET', discoveryUrl);
  return JSON.parse(result.body);
}

/**
 * Gets the ICT Endpoint URL.
 * @param opBaseUrl Base or issuer URL of the OpenID Provider.
 * @param http Optional HTTP Request function. Default is fetch.
 * @returns ICT Endpoint URL.
 * @throws {OidcSquaredNotSupportedError} If endpoint was not found at discovery endpoint.
 */
export async function getIctEndpoint(opBaseUrl: string, http: HttpRequestFunction = FETCH_HTTP_REQUEST_FUNCTION): Promise<string> {
  const opDiscoveryUrl = getDiscoveryUrl(opBaseUrl);
  const opDiscoveryDocument = await requestDiscoveryDocument(opDiscoveryUrl, http);
  if (!opDiscoveryDocument.ict_endpoint) {
    throw new OidcSquaredNotSupportedError();
  }
  return opDiscoveryDocument.ict_endpoint as string;
}
