export type HistoryDirection = "backward" | "forward";

export interface EventsHistoryRequestInput {
  groupChatId: string;
  keyId: string;
  direction: HistoryDirection;
  limit: number;
  syncId?: string;
  toSyncId?: string;
  lastIgnoreMessagesAt?: string | null;
}

export interface EventsHistoryRequest {
  method: "GET";
  url: string;
}

const MAX_HISTORY_PAGE_SIZE = 100;

function requireNonEmpty(value: string, field: string): string {
  if (value.trim().length === 0) {
    throw new TypeError(`${field} must be a non-empty string`);
  }

  return value;
}

function addOptionalString(
  query: URLSearchParams,
  name: string,
  value: string | undefined,
): void {
  if (value === undefined) {
    return;
  }

  query.set(name, requireNonEmpty(value, name));
}

/** Builds the private eXpress Desktop 3.72 history request without credentials. */
export function buildEventsHistoryRequest(
  input: EventsHistoryRequestInput,
): EventsHistoryRequest {
  const groupChatId = requireNonEmpty(input.groupChatId, "groupChatId");
  const keyId = requireNonEmpty(input.keyId, "keyId");

  if (input.direction !== "backward" && input.direction !== "forward") {
    throw new TypeError("direction must be backward or forward");
  }

  if (
    !Number.isSafeInteger(input.limit) ||
    input.limit < 1 ||
    input.limit > MAX_HISTORY_PAGE_SIZE
  ) {
    throw new RangeError(
      `limit must be an integer between 1 and ${MAX_HISTORY_PAGE_SIZE}`,
    );
  }

  const query = new URLSearchParams({
    key_id: keyId,
    direction: input.direction,
    limit: String(input.limit),
  });

  addOptionalString(query, "sync_id", input.syncId);
  addOptionalString(query, "to_sync_id", input.toSyncId);
  query.set("skip_non_affecting_rc", "true");
  query.set("skip_to_sync_id_event", "true");

  if (input.lastIgnoreMessagesAt !== undefined) {
    query.set(
      "last_ignore_messages_at",
      input.lastIgnoreMessagesAt === null
        ? "null"
        : requireNonEmpty(
            input.lastIgnoreMessagesAt,
            "lastIgnoreMessagesAt",
          ),
    );
  }

  return {
    method: "GET",
    url:
      `/api/v1/messaging/events_history/${encodeURIComponent(groupChatId)}` +
      `?${query.toString()}`,
  };
}
