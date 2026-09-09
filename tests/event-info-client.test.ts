import { describe, expect, it, vi } from "vitest";

import type { StandaloneExpressSession } from "../src/auth/standalone-qr-client.js";
import { fetchEventInfo } from "../src/express/event-info-client.js";

describe("event info client", () => {
  it("uses bearer auth and repeated sync_ids parameters", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          status: "ok",
          result: { info: [{ sync_id: "synthetic-sync-1" }] },
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );
    const session = {
      version: 1,
      createdAt: "2026-01-01T00:00:00.000Z",
      rts: {
        host: "synthetic.invalid",
        authToken: "SYNTHETIC_TOKEN",
        expiresAt: null,
        userHuid: "synthetic-user",
        serverId: "synthetic-server",
      },
      device: {
        udid: "synthetic-udid",
        registrationId: "synthetic-registration",
        signingKeyId: "synthetic-signing-id",
        signingAlgorithm: "ed25519",
        signingPublicKey: "SYNTHETIC_PUBLIC",
        signingPrivateKey: "SYNTHETIC_PRIVATE",
      },
      encryptionKeys: { rts_pub_key_id: "synthetic-key-id" },
    } satisfies StandaloneExpressSession;

    await expect(
      fetchEventInfo(session, ["synthetic-sync-1", "synthetic-sync-2"], {
        fetch: fetchMock,
      }),
    ).resolves.toEqual([{ sync_id: "synthetic-sync-1" }]);
    const [url, request] = fetchMock.mock.calls[0]!;
    expect(String(url)).toContain("key_id=synthetic-key-id");
    expect(String(url)).toContain("sync_ids%5B%5D=synthetic-sync-1");
    expect(String(url)).toContain("sync_ids%5B%5D=synthetic-sync-2");
    expect(request.headers.Authorization).toBe("Bearer SYNTHETIC_TOKEN");
  });
});
