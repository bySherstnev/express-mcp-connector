import sodium from "libsodium-wrappers-sumo";

import { signExpressRequest } from "./express-http-signature.js";
import type { StandaloneExpressSession } from "./standalone-qr-client.js";
import { tokenExpiresAt } from "./cts-token-refresh.js";

const EMAIL_REQUEST_PATH = "/api/v4/ad_integration/register_request/email";
const EMAIL_CONFIRM_PATH = "/api/v3/ad_integration/register_confirm/email";

type JsonRecord = Record<string, unknown>;

function asRecord(value: unknown): JsonRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("CTS email authentication returned an invalid response");
  }
  return value as JsonRecord;
}

function requiredString(record: JsonRecord, field: string): string {
  const value = record[field];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error("CTS email authentication returned an invalid response");
  }
  return value;
}

function optionalString(record: JsonRecord, field: string): string | null {
  const value = record[field];
  return typeof value === "string" && value.length > 0 ? value : null;
}

function assertEmail(value: string): string {
  const normalized = value.trim();
  if (
    normalized.length > 320 ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalized)
  ) {
    throw new TypeError("A valid corporate email is required");
  }
  return normalized;
}

async function signedCtsPost(
  session: StandaloneExpressSession,
  host: string,
  target: string,
  bodyValue: JsonRecord,
  options: { fetch?: typeof fetch; signal?: AbortSignal },
): Promise<JsonRecord> {
  await sodium.ready;
  const body = JSON.stringify(bodyValue);
  const signed = signExpressRequest({
    method: "POST",
    target,
    body,
    keyId: session.device.registrationId,
    algorithm: session.device.signingAlgorithm,
    privateKey: sodium.from_base64(
      session.device.signingPrivateKey,
      sodium.base64_variants.ORIGINAL,
    ),
  });
  let response: Response;
  try {
    response = await (options.fetch ?? fetch)(`https://${host}${target}`, {
      method: "POST",
      headers: signed.headers,
      body,
      signal: options.signal,
    });
  } catch {
    throw new Error("CTS email authentication request failed");
  }
  let payload: JsonRecord | null = null;
  try {
    payload = asRecord(await response.json());
  } catch {
    // A proxy or server can return a non-JSON 5xx body.
  }
  if (!response.ok) {
    const reason = payload?.reason;
    const suffix =
      typeof reason === "string" && /^[a-z0-9_.:-]{1,100}$/i.test(reason)
        ? ` (${reason})`
        : "";
    throw new Error(
      `CTS email authentication returned HTTP ${response.status}${suffix}`,
    );
  }
  if (!payload || payload.status !== "ok") {
    const reason = payload?.reason;
    if (
      typeof reason === "string" &&
      /^[a-z0-9_.:-]{1,100}$/i.test(reason)
    ) {
      throw new Error(`CTS email authentication was rejected (${reason})`);
    }
    throw new Error("CTS email authentication was rejected");
  }
  return asRecord(payload.result);
}

/** Requests the six-digit corporate email confirmation code used by 3.72. */
export async function requestCtsEmailCode(
  session: StandaloneExpressSession,
  email: string,
  options: { fetch?: typeof fetch; signal?: AbortSignal } = {},
): Promise<StandaloneExpressSession> {
  const host = session.ctsPending?.host;
  if (!host) {
    throw new Error("CTS host is unavailable in the QR-paired session");
  }
  const normalizedEmail = assertEmail(email);
  const result = await signedCtsPost(
    session,
    host,
    EMAIL_REQUEST_PATH,
    {
      email: normalizedEmail,
      ets: false,
      rts_registration_id: session.device.registrationId,
    },
    options,
  );
  return {
    ...session,
    ctsEmailPending: {
      host,
      registrationId: requiredString(result, "registration_id"),
      email: optionalString(result, "email") ?? normalizedEmail,
    },
  };
}

/** Exchanges the short-lived email code for a revocable CTS device session. */
export async function confirmCtsEmailCode(
  session: StandaloneExpressSession,
  code: string,
  options: { fetch?: typeof fetch; signal?: AbortSignal } = {},
): Promise<StandaloneExpressSession> {
  const pending = session.ctsEmailPending;
  if (!pending) {
    throw new Error("No CTS email confirmation is pending");
  }
  const normalizedCode = code.trim();
  if (!/^\d{6}$/.test(normalizedCode)) {
    throw new TypeError("CTS email confirmation code must contain six digits");
  }
  const result = await signedCtsPost(
    session,
    pending.host,
    EMAIL_CONFIRM_PATH,
    {
      registration_id: pending.registrationId,
      rts_registration_id: session.device.registrationId,
      registration_token: normalizedCode,
      ets: false,
    },
    options,
  );
  const expiresIn = result.expires_in;
  const { ctsPending: _qr, ctsEmailPending: _email, ...base } = session;
  return {
    ...base,
    cts: {
      host: pending.host,
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
