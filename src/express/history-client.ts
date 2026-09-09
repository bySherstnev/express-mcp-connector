import type { StandaloneExpressSession } from "../auth/standalone-qr-client.js";
import {
  connectionKeyField,
  resolveExpressConnection,
  type ExpressConnectionKind,
} from "./connection.js";
import {
  buildEventsHistoryRequest,
  type EventsHistoryRequestInput,
} from "./history-request.js";

type JsonRecord = Record<string, unknown>;

export interface RawHistoryPage {
  events: JsonRecord[];
  generatedAt: string | null;
}

function asRecord(value: unknown, context: string): JsonRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`Invalid ${context} response`);
  }
  return value as JsonRecord;
}

export async function fetchHistoryPage(
  session: StandaloneExpressSession,
  input: Omit<EventsHistoryRequestInput, "keyId">,
  options: {
    fetch?: typeof fetch;
    signal?: AbortSignal;
    connection?: ExpressConnectionKind;
  } = {},
): Promise<RawHistoryPage> {
  const connection = resolveExpressConnection(
    session,
    options.connection ?? "rts",
  );
  const keyId =
    session.encryptionKeys[connectionKeyField(connection, "pub_key_id")];
  if (typeof keyId !== "string" || keyId.length === 0) {
    throw new Error("Stored eXpress encryption keys are incomplete");
  }
  const request = buildEventsHistoryRequest({ ...input, keyId });
  const url = new URL(request.url, `https://${connection.host}`);
  let response: Response;
  try {
    response = await (options.fetch ?? fetch)(url, {
      method: request.method,
      headers: { Authorization: `Bearer ${connection.authToken}` },
      signal: options.signal,
    });
  } catch {
    throw new Error("Events history request failed");
  }
  if (!response.ok) {
    throw new Error(`Events history returned HTTP ${response.status}`);
  }
  let payload: JsonRecord;
  try {
    payload = asRecord(await response.json(), "events history");
  } catch (error) {
    if (error instanceof Error && error.message.startsWith("Invalid")) {
      throw error;
    }
    throw new Error("Events history returned invalid JSON");
  }
  if (payload.status !== "ok") {
    throw new Error("Events history request was rejected");
  }
  const result = asRecord(payload.result, "events history");
  if (!Array.isArray(result.history)) {
    throw new Error("Invalid events history response");
  }
  return {
    events: result.history.map((event) => asRecord(event, "history event")),
    generatedAt:
      typeof result.generated_at === "string" ? result.generated_at : null,
  };
}
