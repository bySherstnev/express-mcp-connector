import sodium from "libsodium-wrappers-sumo";

import { signExpressRequest } from "./express-http-signature.js";
import {
  buildMobileToWebRegistrationRequest,
  type ExpressHttpRequest,
  type QrDeviceMetadata,
  type QrRegistrationState,
} from "./standalone-qr-registration.js";
import { decryptQrRegistrationData } from "./standalone-qr-registration.js";
import { tokenExpiresAt } from "./cts-token-refresh.js";
import { EXPRESS_JSON_HEADERS } from "./express-client-headers.js";

const RTS_CONFIRM_PATH = "/api/v1/authentication/register_confirm/qr";
const CTS_CONFIRM_PATH = "/api/v1/ad_integration/register_confirm/qr";

type JsonRecord = Record<string, unknown>;

export interface StandaloneExpressSession {
  version: 1;
  createdAt: string;
  rts: {
    host: string;
    authToken: string;
    expiresAt: string | null;
    userHuid: string;
    serverId: string;
  };
  cts?: {
    host: string;
    accessToken: string;
    refreshToken: string | null;
    expiresIn: number | null;
    expiresAt?: string | null;
    userHuid: string;
    serverId: string;
    active: boolean;
  };
  ctsPending?: {
    host: string;
    temporaryToken: string;
  };
  ctsEmailPending?: {
    host: string;
    registrationId: string;
    email: string;
  };
  device: {
    udid: string;
    registrationId: string;
    signingKeyId: string;
    signingAlgorithm: string;
    signingPublicKey: string;
    signingPrivateKey: string;
  };
  requestSigning?: {
    publicKeyId: string;
    privateKeyId: string;
    algorithm: string;
    publicKey: string;
    privateKey: string;
    uploaded: boolean;
    uploadedConnections?: Array<"rts" | "cts">;
  };
  serverEncryption?: {
    rtsPublicKey: string;
  };
  encryptionKeys: JsonRecord;
}

export interface CompleteQrRegistrationInput {
  initialRtsHost: string;
  state: QrRegistrationState;
  device: QrDeviceMetadata;
  fetch?: typeof fetch;
  signal?: AbortSignal;
}

function asRecord(value: unknown, context: string): JsonRecord {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`Invalid ${context} response`);
  }
  return value as JsonRecord;
}

function requiredString(record: JsonRecord, field: string, context: string): string {
  const value = record[field];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`Invalid ${context} response`);
  }
  return value;
}

function optionalString(record: JsonRecord, field: string): string | null {
  const value = record[field];
  return typeof value === "string" && value.length > 0 ? value : null;
}

function normalizeHost(host: string): string {
  if (host.trim() !== host || host.length === 0) {
    throw new Error("Invalid registration host");
  }
  try {
    const parsed = new URL(host.includes("://") ? host : `https://${host}`);
    if (
      parsed.protocol !== "https:" ||
      parsed.username.length > 0 ||
      parsed.password.length > 0 ||
      parsed.pathname !== "/" ||
      parsed.search.length > 0 ||
      parsed.hash.length > 0
    ) {
      throw new Error("invalid");
    }
    return parsed.host;
  } catch {
    throw new Error("Invalid registration host");
  }
}

function unwrapOkResponse(value: unknown, context: string): JsonRecord {
  const response = asRecord(value, context);
  if (response.status !== "ok") {
    throw new Error(`${context} was rejected`);
  }
  return asRecord(response.result, context);
}

async function executeJson(
  requestOrFactory: ExpressHttpRequest | (() => ExpressHttpRequest),
  fetchImpl: typeof fetch,
  context: string,
  signal?: AbortSignal,
  retryRequestTimeout = false,
): Promise<unknown> {
  for (let requestTimeouts = 0; ; requestTimeouts += 1) {
    const request =
      typeof requestOrFactory === "function"
        ? requestOrFactory()
        : requestOrFactory;
    let response: Response;
    try {
      response = await fetchImpl(request.url, {
        method: request.method,
        headers: request.headers,
        body: request.body,
        signal,
      });
    } catch {
      if (signal?.aborted) {
        throw new Error(`${context} request was cancelled`);
      }
      throw new Error(`${context} request failed`);
    }
    if (retryRequestTimeout && response.status === 408) {
      if (requestTimeouts >= 120) {
        throw new Error(`${context} polling limit exceeded`);
      }
      await new Promise<void>((resolve, reject) => {
        const done = (): void => {
          signal?.removeEventListener("abort", abort);
          resolve();
        };
        const timer = setTimeout(
          done,
          Math.min(100 * (requestTimeouts + 1), 2_000),
        );
        const abort = (): void => {
          clearTimeout(timer);
          signal?.removeEventListener("abort", abort);
          reject(new Error(`${context} request was cancelled`));
        };
        signal?.addEventListener("abort", abort, { once: true });
        if (signal?.aborted) {
          abort();
        }
      });
      continue;
    }
    if (!response.ok) {
      throw new Error(`${context} returned HTTP ${response.status}`);
    }
    try {
      return await response.json();
    } catch {
      throw new Error(`${context} returned invalid JSON`);
    }
  }
}

function buildSignedPost(
  host: string,
  target: string,
  bodyValue: JsonRecord,
  state: QrRegistrationState,
): ExpressHttpRequest {
  const normalizedHost = normalizeHost(host);
  const body = JSON.stringify(bodyValue);
  const signed = signExpressRequest({
    method: "POST",
    target,
    body,
    keyId: state.registrationId,
    algorithm: state.signingAlgorithm,
    privateKey: state.signingPrivateKey,
    headers: EXPRESS_JSON_HEADERS,
  });
  return {
    method: "POST",
    target,
    url: `https://${normalizedHost}${target}`,
    headers: signed.headers,
    body,
  };
}

/** Completes the 3.72 mobile-to-web QR flow without using an installed client. */
export async function completeQrRegistration(
  input: CompleteQrRegistrationInput,
): Promise<StandaloneExpressSession> {
  await sodium.ready;
  const fetchImpl = input.fetch ?? fetch;

  const approval = unwrapOkResponse(
    await executeJson(
      () =>
        buildMobileToWebRegistrationRequest({
          rtsHost: input.initialRtsHost,
          state: input.state,
          device: input.device,
        }),
      fetchImpl,
      "QR approval",
      input.signal,
      true,
    ),
    "QR approval",
  );
  const mobileRegistrationId = requiredString(
    approval,
    "registration_id",
    "QR approval",
  );
  const encryptedRegistrationData = requiredString(
    approval,
    "registration_data",
    "QR approval",
  );
  const rtsTemporaryToken = requiredString(
    approval,
    "rts_registration_token",
    "QR approval",
  );
  const ctsTemporaryToken = optionalString(
    approval,
    "cts_registration_token",
  );
  const encryptionKeys = asRecord(
    await decryptQrRegistrationData(
      encryptedRegistrationData,
      input.state.registrationKey,
    ),
    "registration data",
  );
  const rtsHost = normalizeHost(
    requiredString(encryptionKeys, "rts_host", "registration data"),
  );

  const rtsRequest = buildSignedPost(
    rtsHost,
    RTS_CONFIRM_PATH,
    {
      registration_id: mobileRegistrationId,
      temp_token: rtsTemporaryToken,
    },
    input.state,
  );
  const rts = unwrapOkResponse(
    await executeJson(rtsRequest, fetchImpl, "RTS confirmation", input.signal),
    "RTS confirmation",
  );

  const session: StandaloneExpressSession = {
    version: 1,
    createdAt: new Date().toISOString(),
    rts: {
      host: rtsHost,
      authToken: requiredString(rts, "auth_token", "RTS confirmation"),
      expiresAt: optionalString(rts, "expires_at"),
      userHuid: requiredString(rts, "user_huid", "RTS confirmation"),
      serverId: requiredString(rts, "server_id", "RTS confirmation"),
    },
    device: {
      udid: input.state.udid,
      registrationId: input.state.registrationId,
      signingKeyId: input.state.registrationId,
      signingAlgorithm: input.state.signingAlgorithm,
      signingPublicKey: sodium.to_base64(
        input.state.signingPublicKey,
        sodium.base64_variants.ORIGINAL,
      ),
      signingPrivateKey: sodium.to_base64(
        input.state.signingPrivateKey,
        sodium.base64_variants.ORIGINAL,
      ),
    },
    encryptionKeys,
  };

  const ctsHostValue = optionalString(encryptionKeys, "cts_host");
  if (ctsHostValue && ctsTemporaryToken) {
    const ctsHost = normalizeHost(ctsHostValue);
    try {
      const ctsRequest = buildSignedPost(
        ctsHost,
        CTS_CONFIRM_PATH,
        {
          rts_registration_id: input.state.registrationId,
          temp_token: ctsTemporaryToken,
          ets: false,
        },
        input.state,
      );
      const cts = unwrapOkResponse(
        await executeJson(
          ctsRequest,
          fetchImpl,
          "CTS confirmation",
          input.signal,
        ),
        "CTS confirmation",
      );
      const expiresIn = cts.expires_in;
      session.cts = {
        host: ctsHost,
        accessToken: requiredString(cts, "access_token", "CTS confirmation"),
        refreshToken: optionalString(cts, "refresh_token"),
        expiresIn: typeof expiresIn === "number" ? expiresIn : null,
        expiresAt: tokenExpiresAt(expiresIn),
        userHuid: optionalString(cts, "user_huid") ?? session.rts.userHuid,
        serverId: requiredString(cts, "server_id", "CTS confirmation"),
        active: typeof cts.active === "boolean" ? cts.active : true,
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : "";
      if (
        /request failed$/.test(message) ||
        /returned HTTP (408|409|429|5\d\d)$/.test(message)
      ) {
        session.ctsPending = {
          host: ctsHost,
          temporaryToken: ctsTemporaryToken,
        };
      } else {
        throw error;
      }
    }
  }

  return session;
}
