import type { StandaloneExpressSession } from "./standalone-qr-client.js";

const CTS_REFRESH_PATH = "/api/v1/ad_integration/token/refresh";

type JsonRecord = Record<string, unknown>;

function asRecord(value: unknown): JsonRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("CTS token refresh returned an invalid response");
  }
  return value as JsonRecord;
}

function requiredString(record: JsonRecord, field: string): string {
  const value = record[field];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error("CTS token refresh returned an invalid response");
  }
  return value;
}

function optionalString(record: JsonRecord, field: string): string | null {
  const value = record[field];
  return typeof value === "string" && value.length > 0 ? value : null;
}

export function tokenExpiresAt(
  expiresIn: unknown,
  now: () => number = Date.now,
): string | null {
  return typeof expiresIn === "number" && Number.isFinite(expiresIn) && expiresIn > 0
    ? new Date(now() + expiresIn * 1_000).toISOString()
    : null;
}

/** Refreshes CTS exactly as the stock 3.72 client does. */
export async function refreshCtsSession(
  session: StandaloneExpressSession,
  options: {
    fetch?: typeof fetch;
    signal?: AbortSignal;
    now?: () => number;
  } = {},
): Promise<StandaloneExpressSession> {
  const cts = session.cts;
  if (!cts?.active || !cts.refreshToken) {
    throw new Error("Corporate eXpress session cannot be refreshed");
  }
  let response: Response;
  try {
    response = await (options.fetch ?? fetch)(
      `https://${cts.host}${CTS_REFRESH_PATH}`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${cts.accessToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ refresh_token: cts.refreshToken }),
        signal: options.signal,
      },
    );
  } catch {
    throw new Error("CTS token refresh request failed");
  }
  if (!response.ok) {
    throw new Error(`CTS token refresh returned HTTP ${response.status}`);
  }
  let payload: JsonRecord;
  try {
    payload = asRecord(await response.json());
  } catch (error) {
    if (error instanceof Error && error.message.includes("invalid response")) {
      throw error;
    }
    throw new Error("CTS token refresh returned invalid JSON");
  }
  if (payload.status !== "ok") {
    throw new Error("CTS token refresh was rejected");
  }
  const result = asRecord(payload.result);
  const expiresIn = result.expires_in;
  return {
    ...session,
    cts: {
      ...cts,
      accessToken: requiredString(result, "cts_access_token"),
      refreshToken: optionalString(result, "refresh_token") ?? cts.refreshToken,
      expiresIn: typeof expiresIn === "number" ? expiresIn : null,
      expiresAt: tokenExpiresAt(expiresIn, options.now),
    },
  };
}

export async function ensureFreshCtsSession(
  session: StandaloneExpressSession,
  options: {
    fetch?: typeof fetch;
    signal?: AbortSignal;
    now?: () => number;
    refreshBeforeMs?: number;
  } = {},
): Promise<StandaloneExpressSession> {
  const expiresAt = session.cts?.expiresAt;
  if (!expiresAt) {
    return session;
  }
  const now = options.now ?? Date.now;
  const refreshBeforeMs = options.refreshBeforeMs ?? 60_000;
  if (Date.parse(expiresAt) - now() > refreshBeforeMs) {
    return session;
  }
  return refreshCtsSession(session, options);
}
