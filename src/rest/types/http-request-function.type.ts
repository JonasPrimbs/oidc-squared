import { HttpMethods } from './http-methods.type';
import { HttpResponse } from './http-response.type';

export type HttpRequestFunction = (method: HttpMethods, url: string, headers?: Headers, body?: string) => Promise<HttpResponse>;

export const FETCH_HTTP_REQUEST_FUNCTION = async (method: HttpMethods, url: string, headers?: Headers, body?: string) => {
  const result = await fetch(url, {
    method: method,
    headers: headers,
    body: body,
  });
  return {
    headers: result.headers,
    body: await result.text(),
    responseCode: result.status,
  };
};
