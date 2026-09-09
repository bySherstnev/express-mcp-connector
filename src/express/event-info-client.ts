import type { StandaloneExpressSession } from "../auth/standalone-qr-client.js";
import {
  connectionKeyField,
  resolveExpressConnection,
  type ExpressConnectionKind,
} from "./connection.js";

type JsonRecord = Record<string, unknown>;

function asRecord(value: unknown, context: string): JsonRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`Invalid ${context} response`);
  }
  return value as JsonRecord;
}

/** Fetches exact events by sync id so the current history anchor is not lost. */
export async function fetchEventInfo(
  session: StandaloneExpressSession,
  syncIds: readonly string[],
  options: {
    fetch?: typeof fetch;
    signal?: AbortSignal;
    connection?: ExpressConnectionKind;
  } = {},
): Promise<JsonRecord[]> {
  const connection = resolveExpressConnection(
    session,
    options.connection ?? "rts",
  );
  const keyId =
    session.encryptionKeys[connectionKeyField(connection, "pub_key_id")];
  if (typeof keyId !== "string" || keyId.length === 0) {
    throw new Error("Stored eXpress encryption keys are incomplete");
  }
  const uniqueIds = [...new Set(syncIds)];
  if (uniqueIds.length === 0 || uniqueIds.some((id) => id.length === 0)) {
    throw new TypeError("Event sync ids are invalid");
  }
  const url = new URL(
    "/api/v1/messaging/events/event_info",
    `https://${connection.host}`,
  );
  url.searchParams.set("key_id", keyId);
  for (const id of uniqueIds) {
    url.searchParams.append("sync_ids[]", id);
  }
  let response: Response;
  try {
    response = await (options.fetch ?? fetch)(url, {
      method: "GET",
      headers: { Authorization: `Bearer ${connection.authToken}` },
      signal: options.signal,
    });
  } catch {
    throw new Error("Event info request failed");
  }
  if (!response.ok) {
    throw new Error(`Event info returned HTTP ${response.status}`);
  }
  let payload: JsonRecord;
  try {
    payload = asRecord(await response.json(), "event info");
  } catch (error) {
    if (error instanceof Error && error.message.startsWith("Invalid")) {
      throw error;
    }
    throw new Error("Event info returned invalid JSON");
  }
  const result = asRecord(payload.result, "event info");
  if (payload.status !== "ok" || !Array.isArray(result.info)) {
    throw new Error("Event info request was rejected");
  }
  return result.info.map((event) => asRecord(event, "event info item"));
}
