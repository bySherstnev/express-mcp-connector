import { describe, expect, it, vi } from "vitest";

import {
  ensureFreshCtsSession,
  refreshCtsSession,
  tokenExpiresAt,
} from "../src/auth/cts-token-refresh.js";
import type { StandaloneExpressSession } from "../src/auth/standalone-qr-client.js";

const SESSION = {
  version: 1,
  createdAt: "2026-01-01T00:00:00.000Z",
  rts: {
    host: "rts.synthetic.invalid",
    authToken: "SYNTHETIC_RTS_TOKEN",
    expiresAt: null,
    userHuid: "synthetic-user",
    serverId: "synthetic-rts",
  },
  cts: {
    host: "cts.synthetic.invalid",
    accessToken: "SYNTHETIC_OLD_CTS_TOKEN",
    refreshToken: "SYNTHETIC_OLD_REFRESH_TOKEN",
    expiresIn: 3600,
    expiresAt: "2026-01-01T00:01:00.000Z",
    userHuid: "synthetic-corporate-user",
    serverId: "synthetic-cts",
    active: true,
  },
  device: {
    udid: "synthetic-udid",
    registrationId: "synthetic-registration",
    signingKeyId: "synthetic-sign-key",
    signingAlgorithm: "ed25519",
    signingPublicKey: "SYNTHETIC_PUBLIC",
    signingPrivateKey: "SYNTHETIC_PRIVATE",
  },
  encryptionKeys: {},
} satisfies StandaloneExpressSession;

describe("CTS token refresh", () => {
  it("treats zero lifetime from QR transfer as no refresh timer", () => {
    expect(tokenExpiresAt(0, () => Date.parse("2026-01-01T00:00:00.000Z"))).toBeNull();
  });

  it("uses the stock 3.72 refresh endpoint and CTS response field", async () => {
    const fetchMock = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      expect(String(url)).toBe(
        "https://cts.synthetic.invalid/api/v1/ad_integration/token/refresh",
      );
      expect(init?.headers).toMatchObject({
        Authorization: "Bearer SYNTHETIC_OLD_CTS_TOKEN",
      });
      expect(JSON.parse(String(init?.body))).toEqual({
        refresh_token: "SYNTHETIC_OLD_REFRESH_TOKEN",
      });
      return new Response(
        JSON.stringify({
          status: "ok",
          result: {
            cts_access_token: "SYNTHETIC_NEW_CTS_TOKEN",
            refresh_token: "SYNTHETIC_NEW_REFRESH_TOKEN",
            expires_in: 7200,
          },
        }),
      );
    });

    const refreshed = await refreshCtsSession(SESSION, {
      fetch: fetchMock as typeof fetch,
      now: () => Date.parse("2026-01-01T01:00:00.000Z"),
    });

    expect(refreshed.cts).toMatchObject({
      accessToken: "SYNTHETIC_NEW_CTS_TOKEN",
      refreshToken: "SYNTHETIC_NEW_REFRESH_TOKEN",
      expiresAt: "2026-01-01T03:00:00.000Z",
    });
  });

  it("does not refresh outside the safety window", async () => {
    const fetchMock = vi.fn();
    const result = await ensureFreshCtsSession(
      {
        ...SESSION,
        cts: { ...SESSION.cts, expiresAt: "2026-01-01T02:00:00.000Z" },
      },
      {
        fetch: fetchMock,
        now: () => Date.parse("2026-01-01T00:00:00.000Z"),
      },
    );

    expect(result.cts?.accessToken).toBe("SYNTHETIC_OLD_CTS_TOKEN");
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
