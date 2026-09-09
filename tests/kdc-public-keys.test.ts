import { describe, expect, it, vi } from "vitest";

import type { StandaloneExpressSession } from "../src/auth/standalone-qr-client.js";
import { fetchKdcPublicKeys } from "../src/express/kdc-public-keys.js";

describe("KDC public key client", () => {
  it("deduplicates ids and authenticates directly to RTS", async () => {
    const session = {
      rts: { host: "rts.synthetic.invalid", authToken: "synthetic-token" },
    } as StandaloneExpressSession;
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(
        JSON.stringify({
          status: "ok",
          result: [
            {
              id: "key-a",
              body: "synthetic-body",
              kind: "rts",
              algo: "xsalsa20",
              user_huid: "synthetic-user",
            },
          ],
        }),
        { status: 200 },
      ),
    );

    const keys = await fetchKdcPublicKeys(
      session,
      ["key-a", "key-a", "key-b"],
      { fetch: fetchMock },
    );

    const url = new URL(fetchMock.mock.calls[0]![0].toString());
    expect(url.pathname).toBe("/api/v1/kdc/keys/");
    expect(url.searchParams.get("ids")).toBe("key-a,key-b");
    expect(fetchMock.mock.calls[0]![1]!.headers).toEqual({
      Authorization: "Bearer synthetic-token",
    });
    expect(keys.get("key-a")?.userHuid).toBe("synthetic-user");
  });

  it("batches a large corporate chat key set", async () => {
    const session = {
      rts: { host: "rts.synthetic.invalid", authToken: "synthetic-token" },
    } as StandaloneExpressSession;
    const fetchMock = vi.fn<typeof fetch>().mockImplementation(async (input) => {
      const ids = new URL(input.toString()).searchParams.get("ids")!.split(",");
      return new Response(
        JSON.stringify({
          status: "ok",
          result: ids.map((id) => ({
            id,
            body: `body-${id}`,
            kind: "rts",
            algo: "xsalsa20",
          })),
        }),
        { status: 200 },
      );
    });
    const ids = Array.from({ length: 205 }, (_unused, index) => `key-${index}`);

    const keys = await fetchKdcPublicKeys(session, ids, { fetch: fetchMock });

    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(keys.size).toBe(205);
  });
});
