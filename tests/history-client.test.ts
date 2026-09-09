import { describe, expect, it, vi } from "vitest";

import type { StandaloneExpressSession } from "../src/auth/standalone-qr-client.js";
import { fetchHistoryPage } from "../src/express/history-client.js";

describe("history client", () => {
  it("uses the standalone RTS key and bearer session", async () => {
    const session = {
      rts: { host: "rts.synthetic.invalid", authToken: "synthetic-token" },
      encryptionKeys: { rts_pub_key_id: "synthetic-key-id" },
    } as StandaloneExpressSession;
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(
        JSON.stringify({
          status: "ok",
          result: {
            history: [{ sync_id: "synthetic-sync", event_type: "message_new" }],
            generated_at: "2026-09-06T12:00:00.000Z",
          },
        }),
        { status: 200 },
      ),
    );

    const page = await fetchHistoryPage(
      session,
      { groupChatId: "synthetic-chat", direction: "backward", limit: 20 },
      { fetch: fetchMock },
    );

    const url = new URL(fetchMock.mock.calls[0]![0].toString());
    expect(url.searchParams.get("key_id")).toBe("synthetic-key-id");
    expect(fetchMock.mock.calls[0]![1]!.headers).toEqual({
      Authorization: "Bearer synthetic-token",
    });
    expect(page.events).toHaveLength(1);
  });

  it("uses the CTS host, token and key for corporate history", async () => {
    const session = {
      cts: {
        host: "cts.synthetic.invalid",
        accessToken: "synthetic-cts-token",
        active: true,
        userHuid: "synthetic-corporate-user",
        serverId: "synthetic-cts",
      },
      encryptionKeys: { cts_pub_key_id: "synthetic-cts-key-id" },
    } as StandaloneExpressSession;
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(
        JSON.stringify({ status: "ok", result: { history: [] } }),
        { status: 200 },
      ),
    );

    await fetchHistoryPage(
      session,
      { groupChatId: "synthetic-chat", direction: "backward", limit: 20 },
      { fetch: fetchMock, connection: "cts" },
    );

    const [url, request] = fetchMock.mock.calls[0]!;
    expect(String(url)).toContain("cts.synthetic.invalid");
    expect(String(url)).toContain("key_id=synthetic-cts-key-id");
    expect(request?.headers).toEqual({
      Authorization: "Bearer synthetic-cts-token",
    });
  });
});
