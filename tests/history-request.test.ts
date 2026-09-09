import { describe, expect, it } from "vitest";

import { buildEventsHistoryRequest } from "../src/express/history-request.js";

describe("eXpress Desktop 3.72 events history request", () => {
  it("builds a backward continuation request with all mandatory safety flags", () => {
    const request = buildEventsHistoryRequest({
      groupChatId: "synthetic-group-fixture",
      keyId: "synthetic-key-fixture",
      direction: "backward",
      limit: 100,
      syncId: "synthetic-continuation-sync",
      lastIgnoreMessagesAt: "2026-01-02T03:04:05.000Z",
    });

    expect(request.method).toBe("GET");

    const url = new URL(request.url, "https://synthetic.invalid");
    expect(url.pathname).toBe(
      "/api/v1/messaging/events_history/synthetic-group-fixture",
    );
    expect(Object.fromEntries(url.searchParams)).toEqual({
      key_id: "synthetic-key-fixture",
      direction: "backward",
      limit: "100",
      sync_id: "synthetic-continuation-sync",
      skip_non_affecting_rc: "true",
      skip_to_sync_id_event: "true",
      last_ignore_messages_at: "2026-01-02T03:04:05.000Z",
    });
  });

  it("omits continuation parameters on the first page but keeps skip flags", () => {
    const request = buildEventsHistoryRequest({
      groupChatId: "synthetic-direct-chat",
      keyId: "synthetic-key-fixture",
      direction: "backward",
      limit: 50,
    });

    const url = new URL(request.url, "https://synthetic.invalid");
    expect(url.searchParams.has("sync_id")).toBe(false);
    expect(url.searchParams.has("to_sync_id")).toBe(false);
    expect(url.searchParams.get("skip_non_affecting_rc")).toBe("true");
    expect(url.searchParams.get("skip_to_sync_id_event")).toBe("true");
  });
});
