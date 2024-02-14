export class AuthorizationResponse {
  uri: string;
  code: string;
  state?: string;

  constructor(uri: string, code: string, state?: string) {
    this.uri = uri;
    this.code = code;
    this.state = state;
  }

  toUri(): string {
    const params: Record<string, string> = { code: this.code };
    if (this.state) {
      params.state = this.state
    }
    return `${this.uri}?${new URLSearchParams(Object.entries(params)).toString()}`;
  }
}
