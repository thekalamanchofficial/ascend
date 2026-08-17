import { apiRequest, apiRequestRaw, ApiError, setAuthToken, getAuthToken } from "../httpClient";

function mockFetchOnce(response: {
  status: number;
  jsonBody?: unknown;
  textBody?: string;
  headers?: Record<string, string>;
}): jest.Mock {
  const headers = new Headers(response.headers ?? {});
  const bodyText = response.textBody ?? (response.jsonBody !== undefined ? JSON.stringify(response.jsonBody) : "");
  const fetchMock = jest.fn().mockResolvedValue({
    status: response.status,
    headers,
    text: async () => bodyText,
    arrayBuffer: async () => new TextEncoder().encode(bodyText).buffer,
  });
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (global as any).fetch = fetchMock;
  return fetchMock;
}

describe("httpClient", () => {
  afterEach(() => {
    setAuthToken(null);
    jest.restoreAllMocks();
  });

  it("apiRequest parses a successful JSON response", async () => {
    mockFetchOnce({ status: 200, jsonBody: { hello: "world" } });
    const result = await apiRequest<{ hello: string }>("/v1/whatever");
    expect(result).toEqual({ hello: "world" });
  });

  it("apiRequest throws ApiError with the server's {error} message on a non-2xx response", async () => {
    mockFetchOnce({ status: 401, jsonBody: { error: "session_token is unknown, expired, or revoked" } });
    await expect(apiRequest("/v1/whatever")).rejects.toMatchObject({
      status: 401,
      message: "session_token is unknown, expired, or revoked",
    } satisfies Partial<ApiError>);
  });

  it("attaches Authorization: Bearer using the centrally-stored token by default", async () => {
    setAuthToken("my-session-token");
    const fetchMock = mockFetchOnce({ status: 200, jsonBody: {} });
    await apiRequest("/v1/whatever");
    const [, init] = fetchMock.mock.calls[0];
    expect(init.headers.Authorization).toBe("Bearer my-session-token");
  });

  it("bearerToken: null suppresses the Authorization header even if a session exists", async () => {
    setAuthToken("my-session-token");
    const fetchMock = mockFetchOnce({ status: 200, jsonBody: {} });
    await apiRequest("/v1/whatever", { bearerToken: null });
    const [, init] = fetchMock.mock.calls[0];
    expect(init.headers.Authorization).toBeUndefined();
  });

  it("an explicit bearerToken overrides the centrally-stored one", async () => {
    setAuthToken("stored-token");
    const fetchMock = mockFetchOnce({ status: 200, jsonBody: {} });
    await apiRequest("/v1/whatever", { bearerToken: "explicit-token" });
    const [, init] = fetchMock.mock.calls[0];
    expect(init.headers.Authorization).toBe("Bearer explicit-token");
  });

  it("getAuthToken reflects setAuthToken", () => {
    expect(getAuthToken()).toBeNull();
    setAuthToken("abc");
    expect(getAuthToken()).toBe("abc");
  });

  it("apiRequestRaw returns raw bytes and the format-version header, not JSON-parsed", async () => {
    mockFetchOnce({ status: 200, textBody: "raw export bytes", headers: { "X-Ascend-Format-Version": "v1" } });
    const result = await apiRequestRaw("/v1/sessionauth/sessions/export", { bearerToken: "tok" });
    expect(new TextDecoder().decode(result.bytes)).toBe("raw export bytes");
    expect(result.formatVersion).toBe("v1");
  });
});
