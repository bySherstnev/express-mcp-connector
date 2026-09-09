import sodium from "libsodium-wrappers-sumo";

import { signExpressRequest } from "./express-http-signature.js";
import { EXPRESS_JSON_HEADERS } from "./express-client-headers.js";
import type { StandaloneExpressSession } from "./standalone-qr-client.js";
import { tokenExpiresAt } from "./cts-token-refresh.js";

const CTS_CONFIRM_PATH = "/api/v1/ad_integration/register_confirm/qr";

type JsonRecord = Record<string, unknown>;

function asRecord(value: unknown): JsonRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("CTS confirmation returned an invalid response");
  }
  return value as JsonRecord;
}

function requiredString(record: JsonRecord, field: string): string {
  const value = record[field];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error("CTS confirmation returned an invalid response");
  }
  return value;
}

function optionalString(record: JsonRecord, field: string): string | null {
  const value = record[field];
  return typeof value === "string" && value.length > 0 ? value : null;
}

async function safeHttpFailure(response: Response): Promise<Error> {
  let suffix = "";
  try {
    const payload = asRecord(await response.json());
    const reason = payload.reason;
    if (
      typeof reason === "string" &&
      /^[a-z0-9_.:-]{1,100}$/i.test(reason)
    ) {
      suffix = ` (${reason})`;
    }
  } catch {
    // Error bodies are optional and must never be reflected verbatim.
  }
  const requestId =
    response.headers.get("x-request-id") ??
    response.headers.get("x-correlation-id") ??
    response.headers.get("request-id");
  if (requestId && /^[a-z0-9_.:-]{1,100}$/i.test(requestId)) {
    suffix += ` [request-id: ${requestId}]`;
  }
  return new Error(`CTS confirmation returned HTTP ${response.status}${suffix}`);
}

/** Retries the one-time CTS leg while preserving the already valid RTS session. */
export async function confirmPendingCtsSession(
  session: StandaloneExpressSession,
  options: {
    fetch?: typeof fetch;
    signal?: AbortSignal;
    ets?: boolean;
  } = {},
): Promise<StandaloneExpressSession> {
  if (!session.ctsPending) {
    return session;
  }
  await sodium.ready;
  const body = JSON.stringify({
    rts_registration_id: session.device.registrationId,
    temp_token: session.ctsPending.temporaryToken,
    ets: options.ets ?? false,
  });
  const signed = signExpressRequest({
    method: "POST",
    target: CTS_CONFIRM_PATH,
    body,
    keyId: session.device.registrationId,
    algorithm: session.device.signingAlgorithm,
    privateKey: sodium.from_base64(
      session.device.signingPrivateKey,
      sodium.base64_variants.ORIGINAL,
    ),
    headers: EXPRESS_JSON_HEADERS,
  });
  let response: Response;
  try {
    response = await (options.fetch ?? fetch)(
      `https://${session.ctsPending.host}${CTS_CONFIRM_PATH}`,
      {
        method: "POST",
        headers: signed.headers,
        body,
        signal: options.signal,
      },
    );
  } catch {
    throw new Error("CTS confirmation request failed");
  }
  if (!response.ok) {
    throw await safeHttpFailure(response);
  }
  let payload: JsonRecord;
  try {
    payload = asRecord(await response.json());
  } catch (error) {
    if (error instanceof Error && error.message.includes("invalid response")) {
      throw error;
    }
    throw new Error("CTS confirmation returned invalid JSON");
  }
  if (payload.status !== "ok") {
    throw new Error("CTS confirmation was rejected");
  }
  const result = asRecord(payload.result);
  const expiresIn = result.expires_in;
  const { ctsPending: _pending, ...withoutPending } = session;
  return {
    ...withoutPending,
    cts: {
      host: session.ctsPending.host,
      accessToken: requiredString(result, "access_token"),
      refreshToken: optionalString(result, "refresh_token"),
      expiresIn: typeof expiresIn === "number" ? expiresIn : null,
      expiresAt: tokenExpiresAt(expiresIn),
      userHuid: optionalString(result, "user_huid") ?? session.rts.userHuid,
      serverId: requiredString(result, "server_id"),
      active: typeof result.active === "boolean" ? result.active : true,
    },
  };
}
