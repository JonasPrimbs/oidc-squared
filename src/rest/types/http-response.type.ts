
export interface HttpResponse {

  /**
   * Body of an HTTP body.
   */
  body: string;

  /**
   * Headers of an HTTP response.
   */
  headers: Headers;

  /**
   * Response code of an HTTP response.
   */
  responseCode: number;
}
