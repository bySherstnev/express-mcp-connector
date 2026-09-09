import { randomUUID } from "node:crypto";

import sodium from "libsodium-wrappers-sumo";

import type { StandaloneExpressSession } from "./standalone-qr-client.js";
import {
  resolveExpressConnection,
  type ExpressConnectionKind,
} from "../express/connection.js";

type JsonRecord = Record<string, unknown>;

export interface RtsBootstrapRequest {
  method: "POST";
  url: string;
  target: string;
  headers: Record<string, string>;
  body: string;
}

function requiredSessionString(
  session: StandaloneExpressSession,
  field: string,
): string {
  const value = session.encryptionKeys[field];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error("Stored eXpress encryption keys are incomplete");
  }
  return value;
}

function decodeBase64Key(value: string, length: number): Uint8Array {
  let decoded: Uint8Array;
  try {
    decoded = sodium.from_base64(value, sodium.base64_variants.ORIGINAL);
  } catch {
    throw new Error("Stored eXpress encryption key is invalid");
  }
  if (decoded.length !== length) {
    throw new Error("Stored eXpress encryption key has an invalid length");
  }
  return decoded;
}

export async function prepareRtsRequestIdentity(
  session: StandaloneExpressSession,
): Promise<StandaloneExpressSession> {
  await sodium.ready;
  if (session.requestSigning) {
    return session;
  }
  const keys = sodium.crypto_sign_keypair();
  return {
    ...session,
    requestSigning: {
      publicKeyId: randomUUID(),
      privateKeyId: randomUUID(),
      algorithm: keys.keyType,
      publicKey: sodium.to_base64(
        keys.publicKey,
        sodium.base64_variants.ORIGINAL,
      ),
      privateKey: sodium.to_base64(
        keys.privateKey,
        sodium.base64_variants.ORIGINAL,
      ),
      uploaded: false,
    },
  };
}

export async function fetchRtsServerPublicKey(
  session: StandaloneExpressSession,
  fetchImpl: typeof fetch = fetch,
  signal?: AbortSignal,
): Promise<StandaloneExpressSession> {
  await sodium.ready;
  let response: Response;
  try {
    response = await fetchImpl(
      `https://${session.rts.host}/api/v1/kdc/start`,
      { method: "GET", signal },
    );
  } catch {
    throw new Error("RTS KDC request failed");
  }
  if (!response.ok) {
    throw new Error(`RTS KDC returned HTTP ${response.status}`);
  }
  let payload: JsonRecord;
  try {
    payload = (await response.json()) as JsonRecord;
  } catch {
    throw new Error("RTS KDC returned invalid JSON");
  }
  if (payload.status !== "ok" || typeof payload.result !== "string") {
    throw new Error("RTS KDC rejected the request");
  }
  decodeBase64Key(payload.result, sodium.crypto_box_PUBLICKEYBYTES);
  return {
    ...session,
    serverEncryption: { rtsPublicKey: payload.result },
  };
}

export async function buildUploadSigningKeyRequest(
  session: StandaloneExpressSession,
  connectionKind: ExpressConnectionKind = "rts",
): Promise<RtsBootstrapRequest> {
  await sodium.ready;
  const signing = session.requestSigning;
  if (!signing) {
    throw new Error("RTS request identity is not prepared");
  }
  const connection = resolveExpressConnection(session, connectionKind);
  const target = `/api/v2/kdc/keys/${encodeURIComponent(connection.userHuid)}`;
  const body = JSON.stringify({
    key: signing.publicKey,
    kind: signing.algorithm,
    algo: requiredSessionString(
      session,
      `${connection.keyPrefix}_key_algo`,
    ),
    id: signing.publicKeyId,
  });
  return {
    method: "POST",
    url: `https://${connection.host}${target}`,
    target,
    headers: {
      Authorization: `Bearer ${connection.authToken}`,
      "Content-Type": "application/json",
    },
    body,
  };
}

export async function uploadRtsRequestIdentity(
  session: StandaloneExpressSession,
  fetchImpl: typeof fetch = fetch,
  signal?: AbortSignal,
  connectionKind: ExpressConnectionKind = "rts",
): Promise<StandaloneExpressSession> {
  const request = await buildUploadSigningKeyRequest(session, connectionKind);
  let response: Response;
  try {
    response = await fetchImpl(request.url, {
      method: request.method,
      headers: request.headers,
      body: request.body,
      signal,
    });
  } catch {
    throw new Error("RTS signing-key upload failed");
  }
  if (!response.ok) {
    throw new Error(`RTS signing-key upload returned HTTP ${response.status}`);
  }
  let payload: JsonRecord;
  try {
    payload = (await response.json()) as JsonRecord;
  } catch {
    throw new Error("RTS signing-key upload returned invalid JSON");
  }
  if (payload.status !== "ok") {
    throw new Error("RTS signing-key upload was rejected");
  }
  return {
    ...session,
    requestSigning: {
      ...session.requestSigning!,
      uploaded: true,
      uploadedConnections: [
        ...new Set([
          ...(session.requestSigning?.uploadedConnections ?? []),
          connectionKind,
        ]),
      ],
    },
  };
}

export function uploadCtsRequestIdentity(
  session: StandaloneExpressSession,
  fetchImpl: typeof fetch = fetch,
  signal?: AbortSignal,
): Promise<StandaloneExpressSession> {
  return uploadRtsRequestIdentity(session, fetchImpl, signal, "cts");
}

/**
 * Makes one request-signing identity usable on every requested connection.
 * The same device key may be registered independently on RTS and CTS.
 */
export async function ensureRequestIdentity(
  session: StandaloneExpressSession,
  connections: readonly ExpressConnectionKind[],
  fetchImpl: typeof fetch = fetch,
  signal?: AbortSignal,
): Promise<StandaloneExpressSession> {
  let current = await prepareRtsRequestIdentity(session);
  const uploaded = new Set(
    current.requestSigning?.uploadedConnections ?? [],
  );
  for (const connection of new Set(connections)) {
    if (uploaded.has(connection)) {
      continue;
    }
    current = await uploadRtsRequestIdentity(
      current,
      fetchImpl,
      signal,
      connection,
    );
    uploaded.add(connection);
  }
  return current;
}
