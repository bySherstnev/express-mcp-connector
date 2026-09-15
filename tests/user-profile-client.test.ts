import { describe, expect, it, vi } from "vitest";

import type { StandaloneExpressSession } from "../src/auth/standalone-qr-client.js";
import { fetchExpressUserProfiles } from "../src/express/user-profile-client.js";

const SESSION = {
  rts: {
    host: "rts.synthetic.invalid",
    authToken: "SYNTHETIC_RTS_TOKEN",
    userHuid: "synthetic-user",
    serverId: "synthetic-rts-server",
  },
  cts: {
    host: "cts.synthetic.invalid",
    accessToken: "SYNTHETIC_CTS_TOKEN",
    refreshToken: null,
    expiresIn: null,
    expiresAt: null,
    userHuid: "synthetic-user",
    serverId: "synthetic-cts-server",
    active: true,
  },
} as StandaloneExpressSession;

describe("eXpress user profile client", () => {
  it("batches corporate HUIDs and keeps only authoritative directory names", async () => {
    const fetchMock = vi.fn<typeof fetch>().mockImplementation(async (_input, init) => {
      const body = JSON.parse(init!.body as string) as { huids: string[] };
      return new Response(
        JSON.stringify({
          status: "ok",
          result: [
            {
              server_id: "synthetic-cts-server",
              cts_profiles: body.huids.map((userHuid, index) => ({
                user_huid: userHuid,
                name: index === 0 ? ` User ${userHuid} ` : null,
              })),
            },
          ],
        }),
        { status: 200 },
      );
    });
    const huids = Array.from({ length: 101 }, (_unused, index) => `user-${index}`);

    const profiles = await fetchExpressUserProfiles(
      SESSION,
      [...huids, huids[0]!],
      { connection: "cts", fetch: fetchMock },
    );

    expect(fetchMock).toHaveBeenCalledTimes(2);
    const firstUrl = new URL(fetchMock.mock.calls[0]![0].toString());
    expect(firstUrl.pathname).toBe("/api/v1/phonebook/cts_profiles/query");
    expect(fetchMock.mock.calls[0]![1]!.headers).toEqual({
      Authorization: "Bearer SYNTHETIC_CTS_TOKEN",
      "Content-Type": "application/json",
    });
    expect(profiles.get("user-0")).toEqual({
      userHuid: "user-0",
      name: "User user-0",
    });
    expect(profiles.get("user-1")?.name).toBeNull();
  });

  it("uses the personal directory and does not invent a missing name", async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(
        JSON.stringify({
          status: "ok",
          result: {
            profiles: [
              {
                user_huid: "known-user",
                rts_profile: { name: "Known User" },
                cts_public_profile: null,
              },
              {
                user_huid: "unknown-user",
                rts_profile: null,
                cts_public_profile: null,
              },
            ],
          },
        }),
        { status: 200 },
      ),
    );

    const profiles = await fetchExpressUserProfiles(
      SESSION,
      ["known-user", "unknown-user", "missing-user"],
      { connection: "rts", fetch: fetchMock },
    );

    const url = new URL(fetchMock.mock.calls[0]![0].toString());
    expect(url.pathname).toBe("/api/v3/phonebook/profiles/query");
    expect(profiles.get("known-user")?.name).toBe("Known User");
    expect(profiles.get("unknown-user")?.name).toBeNull();
    expect(profiles.has("missing-user")).toBe(false);
  });
});
