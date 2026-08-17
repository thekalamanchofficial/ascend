// Shared HTTP layer for every server-backed capability client under
// apps/mobile/src/capabilities/**. Per apps/mobile/README.md's capability
// boundary, this file holds no capability logic of its own — it only knows
// how to shape an HTTP request/response and where the server lives. What a
// given path/body means is entirely owned by the capability module calling
// it (identity/index.ts, sessionauth/index.ts, ...).
//
// Base URL: EXPO_PUBLIC_API_URL is Expo's documented convention for a
// public (bundled-into-the-client, non-secret) env var — see
// https://docs.expo.dev/guides/environment-variables/. Defaults to
// http://localhost:8080 for local dev against `cd services/api && go run .`
// (see services/api/README.md / docker-compose.yml for bringing the local
// stack up). This is never a secret — it is the same base URL a browser's
// network tab would show regardless.
//
// CORS note (only relevant for `expo start --web`, never for native iOS/
// Android, which don't go through a browser CORS check at all):
// services/api/main.go's corsAllowedOrigins() is already dev-scoped open
// for http://localhost:8081 (Expo/Metro default), :19006 (legacy Expo web
// default), and :3000 — see docs/DECISION_LOG.md, 2026-08-17, "Dev-scoped
// CORS on services/api, for expo web/UI dev tooling". Nothing in this file
// needs to special-case web vs. native; the server already allows the dev
// origins a browser-hosted Expo app would present.
function getApiBaseUrl(): string {
  return process.env.EXPO_PUBLIC_API_URL || "http://localhost:8080";
}

/**
 * Thrown for every non-2xx response. `body` is the parsed `{ error: string }`
 * shape every capability's Go handler writes on failure (see e.g.
 * services/api/internal/identity/http.go's writeError), when the response
 * was JSON; otherwise the raw response text.
 */
export class ApiError extends Error {
  readonly status: number;
  readonly body: unknown;

  constructor(status: number, message: string, body: unknown) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.body = body;
  }
}

// Centrally-held bearer token, so a capability client doesn't have to thread
// a session token through every call by hand once a session exists. Any
// individual request can still override this (or explicitly opt out with
// `bearerToken: null`) via RequestOptions below — needed because
// SessionAuth's own IssueSession/GetSessionChallenge/RevokeSession calls
// happen *before* a session exists, and RevokeAllSessions/ExportSessions
// intentionally take a caller-supplied token that may not be "the" current
// session (e.g. revoking a different, still-known session).
let currentSessionToken: string | null = null;

export function setAuthToken(token: string | null): void {
  currentSessionToken = token;
}

export function getAuthToken(): string | null {
  return currentSessionToken;
}

export interface RequestOptions {
  method?: "GET" | "POST" | "PUT" | "DELETE" | "PATCH";
  /** JSON-serializable request body. Omit for GET/DELETE requests with no body. */
  body?: unknown;
  /**
   * Overrides the centrally-stored token for this one request. Pass `null`
   * explicitly to send no Authorization header even if a session exists
   * (e.g. the public CreateIdentity/ResolveIdentity/BindDevice routes).
   * Omit entirely to use whatever setAuthToken() last set (may also be
   * absent, which is fine for public routes).
   */
  bearerToken?: string | null;
}

/**
 * Issues a request expecting a JSON `{ ... }` response body (every RPC in
 * this codebase except SessionAuth's ExportSessions, which returns a raw
 * byte body — see apiRequestRaw below).
 */
export async function apiRequest<TResponse>(path: string, options: RequestOptions = {}): Promise<TResponse> {
  const { status, headers, bodyText } = await rawFetch(path, options);
  const parsed = bodyText.length > 0 ? safeJsonParse(bodyText) : undefined;

  if (status < 200 || status >= 300) {
    const message =
      parsed && typeof parsed === "object" && parsed !== null && "error" in parsed
        ? String((parsed as { error: unknown }).error)
        : `Request to ${path} failed with status ${status}`;
    throw new ApiError(status, message, parsed ?? bodyText);
  }

  void headers; // reserved for a future caller that needs response headers on the JSON path
  return parsed as TResponse;
}

/**
 * Issues a request expecting a raw (non-JSON) byte body — SessionAuth's
 * ExportSessions returns the export blob directly as the response body,
 * with its format version carried in the X-Ascend-Format-Version header
 * (see services/api/internal/sessionauth/http.go's handleExportSessions),
 * not wrapped in a JSON envelope like every other RPC.
 */
export async function apiRequestRaw(
  path: string,
  options: RequestOptions = {},
): Promise<{ bytes: Uint8Array; formatVersion: string | null }> {
  const url = `${getApiBaseUrl()}${path}`;
  const headers = buildHeaders(options, /* hasBody */ false);

  const res = await fetch(url, { method: options.method ?? "GET", headers });
  if (res.status < 200 || res.status >= 300) {
    const text = await res.text();
    const parsed = safeJsonParse(text);
    const message =
      parsed && typeof parsed === "object" && parsed !== null && "error" in parsed
        ? String((parsed as { error: unknown }).error)
        : `Request to ${path} failed with status ${res.status}`;
    throw new ApiError(res.status, message, parsed ?? text);
  }

  const arrayBuffer = await res.arrayBuffer();
  return {
    bytes: new Uint8Array(arrayBuffer),
    formatVersion: res.headers.get("X-Ascend-Format-Version"),
  };
}

async function rawFetch(
  path: string,
  options: RequestOptions,
): Promise<{ status: number; headers: Headers; bodyText: string }> {
  const url = `${getApiBaseUrl()}${path}`;
  const hasBody = options.body !== undefined;
  const headers = buildHeaders(options, hasBody);

  const res = await fetch(url, {
    method: options.method ?? "GET",
    headers,
    body: hasBody ? JSON.stringify(options.body) : undefined,
  });

  const bodyText = await res.text();
  return { status: res.status, headers: res.headers, bodyText };
}

function buildHeaders(options: RequestOptions, hasBody: boolean): Record<string, string> {
  const headers: Record<string, string> = {};
  if (hasBody) headers["Content-Type"] = "application/json";

  const token = options.bearerToken === undefined ? currentSessionToken : options.bearerToken;
  if (token) headers["Authorization"] = `Bearer ${token}`;

  return headers;
}

function safeJsonParse(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}
