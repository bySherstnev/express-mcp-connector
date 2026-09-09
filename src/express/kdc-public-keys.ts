import type { StandaloneExpressSession } from "../auth/standalone-qr-client.js";
import {
  resolveExpressConnection,
  type ExpressConnectionKind,
} from "./connection.js";

type JsonRecord = Record<string, unknown>;
const MAX_KEY_IDS_PER_REQUEST = 100;

export interface ExpressPublicKey {
  id: string;
  body: string;
  kind: string;
  algo: string;
  userHuid: string | null;
}

function asRecord(value: unknown, context: string): JsonRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`Invalid ${context} response`);
  }
  return value as JsonRecord;
}

export async function fetchKdcPublicKeys(
  session: StandaloneExpressSession,
  ids: readonly string[],
  options: {
    fetch?: typeof fetch;
    signal?: AbortSignal;
    connection?: ExpressConnectionKind;
  } = {},
): Promise<Map<string, ExpressPublicKey>> {
  const connection = resolveExpressConnection(
    session,
    options.connection ?? "rts",
  );
  const uniqueIds = [...new Set(ids)];
  if (
    uniqueIds.length === 0 ||
    uniqueIds.some((id) => id.length === 0 || id.includes(","))
  ) {
    throw new TypeError("KDC key ids are invalid");
  }
  const keys = new Map<string, ExpressPublicKey>();
  const fetchImpl = options.fetch ?? fetch;
  for (let offset = 0; offset < uniqueIds.length; offset += MAX_KEY_IDS_PER_REQUEST) {
    const batch = uniqueIds.slice(offset, offset + MAX_KEY_IDS_PER_REQUEST);
    const requested = new Set(batch);
    const url = new URL("/api/v1/kdc/keys/", `https://${connection.host}`);
    url.searchParams.set("ids", batch.join(","));
    let response: Response;
    try {
      response = await fetchImpl(url, {
        method: "GET",
        headers: { Authorization: `Bearer ${connection.authToken}` },
        signal: options.signal,
      });
    } catch {
      throw new Error("KDC public keys request failed");
    }
    if (!response.ok) {
      throw new Error(`KDC public keys returned HTTP ${response.status}`);
    }
    let payload: JsonRecord;
    try {
      payload = asRecord(await response.json(), "KDC public keys");
    } catch (error) {
      if (error instanceof Error && error.message.startsWith("Invalid")) {
        throw error;
      }
      throw new Error("KDC public keys returned invalid JSON");
    }
    if (payload.status !== "ok" || !Array.isArray(payload.result)) {
      throw new Error("KDC public keys request was rejected");
    }
    for (const item of payload.result) {
      const key = asRecord(item, "KDC public key");
      if (
        typeof key.id !== "string" ||
        typeof key.body !== "string" ||
        typeof key.kind !== "string" ||
        typeof key.algo !== "string"
      ) {
        throw new Error("Invalid KDC public key response");
      }
      if (!requested.has(key.id)) {
        continue;
      }
      keys.set(key.id, {
        id: key.id,
        body: key.body,
        kind: key.kind,
        algo: key.algo,
        userHuid: typeof key.user_huid === "string" ? key.user_huid : null,
      });
    }
  }
  return keys;
}
