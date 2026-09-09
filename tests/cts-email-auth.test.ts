import sodium from "libsodium-wrappers-sumo";
import { describe, expect, it, vi } from "vitest";

import {
  confirmCtsEmailCode,
  requestCtsEmailCode,
} from "../src/auth/cts-email-auth.js";
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
      temporaryToken: "SYNTHETIC_QR_TEMP",
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

describe("CTS corporate email authentication", () => {
  it("requests a code with the signed 3.72 email contract", async () => {
    const session = await sessionFixture();
    const fetchMock = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      expect(String(url)).toBe(
        "https://cts.synthetic.invalid/api/v4/ad_integration/register_request/email",
      );
      expect(JSON.parse(String(init?.body))).toEqual({
        email: "person@example.invalid",
        ets: false,
        rts_registration_id: "synthetic-registration-id",
      });
      expect(init?.headers).toMatchObject({ Signature: expect.any(String) });
      return new Response(
        JSON.stringify({
          status: "ok",
          result: {
            registration_id: "synthetic-cts-registration",
            email: "masked@example.invalid",
          },
        }),
        { status: 200 },
      );
    });

    const updated = await requestCtsEmailCode(
      session,
      "person@example.invalid",
      { fetch: fetchMock as typeof fetch },
    );

    expect(updated.ctsEmailPending).toEqual({
      host: "cts.synthetic.invalid",
      registrationId: "synthetic-cts-registration",
      email: "masked@example.invalid",
    });
  });

  it("exchanges the code and removes both pending credentials", async () => {
    const session = {
      ...(await sessionFixture()),
      ctsEmailPending: {
        host: "cts.synthetic.invalid",
        registrationId: "synthetic-cts-registration",
        email: "masked@example.invalid",
      },
    };
    const fetchMock = vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
      expect(JSON.parse(String(init?.body))).toEqual({
        registration_id: "synthetic-cts-registration",
        rts_registration_id: "synthetic-registration-id",
        registration_token: "123456",
        ets: false,
      });
      return new Response(
        JSON.stringify({
          status: "ok",
          result: {
            access_token: "SYNTHETIC_CTS_TOKEN",
            refresh_token: "SYNTHETIC_CTS_REFRESH",
            expires_in: 3600,
            user_huid: "synthetic-corporate-user",
            server_id: "synthetic-cts-server",
            active: true,
          },
        }),
        { status: 200 },
      );
    });

    const updated = await confirmCtsEmailCode(session, "123456", {
      fetch: fetchMock as typeof fetch,
    });

    expect(updated.ctsPending).toBeUndefined();
    expect(updated.ctsEmailPending).toBeUndefined();
    expect(updated.cts).toMatchObject({
      accessToken: "SYNTHETIC_CTS_TOKEN",
      userHuid: "synthetic-corporate-user",
      active: true,
    });
  });
});
