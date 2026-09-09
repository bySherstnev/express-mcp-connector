import sodium from "libsodium-wrappers-sumo";
import { describe, expect, it, vi } from "vitest";

import { confirmPendingCtsSession } from "../src/auth/cts-session-confirmation.js";
import type { StandaloneExpressSession } from "../src/auth/standalone-qr-client.js";

async function sessionFixture(): Promise<StandaloneExpressSession> {
  await sodium.ready;
  const signing = sodium.crypto_sign_keypair();
  return {
    version: 1,
    createdAt: "2026-01-01T00:00:00.000Z",
    rts: {
      host: "rts.synthetic.invalid",
      authToken: "SYNTHETIC_RTS_TOKEN",
      expiresAt: null,
      userHuid: "synthetic-user",
      serverId: "synthetic-rts",
    },
    ctsPending: {
      host: "cts.synthetic.invalid",
      temporaryToken: "SYNTHETIC_TEMP_TOKEN",
    },
    device: {
      udid: "synthetic-udid",
      registrationId: "synthetic-registration-id",
      signingKeyId: "synthetic-signing-id",
      signingAlgorithm: signing.keyType,
      signingPublicKey: sodium.to_base64(
        signing.publicKey,
        sodium.base64_variants.ORIGINAL,
      ),
      signingPrivateKey: sodium.to_base64(
        signing.privateKey,
        sodium.base64_variants.ORIGINAL,
      ),
    },
    encryptionKeys: {},
  };
}

describe("pending CTS confirmation", () => {
  it("promotes an accepted pending token without changing the RTS session", async () => {
    const session = await sessionFixture();
    const fetchImpl = vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
      expect(JSON.parse(String(init?.body))).toEqual({
        rts_registration_id: "synthetic-registration-id",
        temp_token: "SYNTHETIC_TEMP_TOKEN",
        ets: false,
      });
      expect(init?.headers).toMatchObject({ Signature: expect.any(String) });
      return new Response(
        JSON.stringify({
          status: "ok",
          result: {
            access_token: "SYNTHETIC_CTS_TOKEN",
            refresh_token: "SYNTHETIC_REFRESH_TOKEN",
            expires_in: 3600,
            server_id: "synthetic-cts",
          },
        }),
        { status: 200 },
      );
    });

    const updated = await confirmPendingCtsSession(session, {
      fetch: fetchImpl as typeof fetch,
    });

    expect(updated.rts).toEqual(session.rts);
    expect(updated.ctsPending).toBeUndefined();
    expect(updated.cts).toMatchObject({
      host: "cts.synthetic.invalid",
      accessToken: "SYNTHETIC_CTS_TOKEN",
      serverId: "synthetic-cts",
    });
  });

  it("preserves the caller's session object when the server still fails", async () => {
    const session = await sessionFixture();
    await expect(
      confirmPendingCtsSession(session, {
        fetch: vi.fn(async () => new Response(null, { status: 500 })) as typeof fetch,
      }),
    ).rejects.toThrow("HTTP 500");
    expect(session.ctsPending?.temporaryToken).toBe("SYNTHETIC_TEMP_TOKEN");
    expect(session.cts).toBeUndefined();
  });

  it("reports only a safe machine reason from a failed response", async () => {
    const session = await sessionFixture();
    await expect(
      confirmPendingCtsSession(session, {
        fetch: vi.fn(
          async () =>
            new Response(
              JSON.stringify({
                reason: "registration_timeout",
                secret: "MUST_NOT_BE_REFLECTED",
              }),
              { status: 500 },
            ),
        ) as typeof fetch,
      }),
    ).rejects.toThrow("HTTP 500 (registration_timeout)");
    await expect(
      confirmPendingCtsSession(session, {
        fetch: vi.fn(
          async () =>
            new Response(JSON.stringify({ reason: "do not leak: TOKEN" }), {
              status: 500,
            }),
        ) as typeof fetch,
      }),
    ).rejects.not.toThrow("TOKEN");
  });

  it("reports a safe request id from a failed response", async () => {
    const session = await sessionFixture();
    await expect(
      confirmPendingCtsSession(session, {
        fetch: vi.fn(
          async () =>
            new Response(JSON.stringify({ status: "error" }), {
              status: 500,
              headers: { "x-request-id": "synthetic-request-id" },
            }),
        ) as typeof fetch,
      }),
    ).rejects.toThrow("[request-id: synthetic-request-id]");
  });
});
