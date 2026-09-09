import { describe, expect, it, vi } from "vitest";
import sodium from "libsodium-wrappers-sumo";

import {
  completeQrRegistration,
  type StandaloneExpressSession,
} from "../src/auth/standalone-qr-client.js";
import { createQrRegistrationState } from "../src/auth/standalone-qr-registration.js";

function join(left: Uint8Array, right: Uint8Array): Uint8Array {
  const result = new Uint8Array(left.length + right.length);
  result.set(left);
  result.set(right, left.length);
  return result;
}

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

describe("standalone QR client", () => {
  it("exchanges the mobile approval for RTS and CTS sessions", async () => {
    await sodium.ready;
    const state = await createQrRegistrationState();
    const transferred = {
      rts_host: "https://ru.public.express",
      cts_host: "https://cts.synthetic.invalid:8443",
      cts_login: "synthetic@example.invalid",
      phone: "+00000000000",
      region: "ru",
      rts_key_algo: "xsalsa20",
      rts_pub_key_id: "synthetic-rts-pub",
      rts_pub_key_body: "SYNTHETIC_RTS_PUBLIC",
      rts_priv_key_id: "synthetic-rts-private",
      rts_priv_key_body: "SYNTHETIC_RTS_PRIVATE",
      cts_key_algo: "xsalsa20",
      cts_pub_key_id: "synthetic-cts-pub",
      cts_pub_key_body: "SYNTHETIC_CTS_PUBLIC",
      cts_priv_key_id: "synthetic-cts-private",
      cts_priv_key_body: "SYNTHETIC_CTS_PRIVATE",
    };
    const nonce = Uint8Array.from(
      { length: sodium.crypto_secretbox_NONCEBYTES },
      (_, i) => i + 3,
    );
    const encryptedRegistrationData = sodium.to_base64(
      join(
        nonce,
        sodium.crypto_secretbox_easy(
          sodium.from_string(JSON.stringify(transferred)),
          nonce,
          state.registrationKey,
        ),
      ),
      sodium.base64_variants.ORIGINAL,
    );

    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(new Response(null, { status: 408 }))
      .mockResolvedValueOnce(
        jsonResponse({
          status: "ok",
          result: {
            registration_id: "synthetic-mobile-registration",
            registration_data: encryptedRegistrationData,
            rts_registration_token: "synthetic-rts-temp-token",
            cts_registration_token: "synthetic-cts-temp-token",
          },
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse({
          status: "ok",
          result: {
            auth_token: "synthetic-rts-auth",
            expires_at: "2027-01-01T00:00:00.000Z",
            user_huid: "synthetic-user",
            server_id: "synthetic-rts-server",
          },
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse({
          status: "ok",
          result: {
            access_token: "synthetic-cts-auth",
            refresh_token: "synthetic-cts-refresh",
            expires_in: 3600,
            server_id: "synthetic-cts-server",
          },
        }),
      );

    const session: StandaloneExpressSession = await completeQrRegistration({
      initialRtsHost: "ru.public.express",
      state,
      device: {
        device: "Desktop 3.72.37",
        deviceSoftware: "macOS",
        deviceHostname: "connector",
        manufacturer: "Apple",
        platform: "desktop",
        locale: "ru",
        timezone: "Europe/Moscow",
      },
      fetch: fetchMock,
    });

    expect(fetchMock).toHaveBeenCalledTimes(4);
    expect(
      (fetchMock.mock.calls[0]![1]!.headers as Record<string, string>)[
        "Express-Request-Nonce"
      ],
    ).not.toBe(
      (fetchMock.mock.calls[1]![1]!.headers as Record<string, string>)[
        "Express-Request-Nonce"
      ],
    );
    expect(fetchMock.mock.calls.map(([url]) => url)).toEqual([
      "https://ru.public.express/api/v1/authentication/qr/mobile_to_web/request",
      "https://ru.public.express/api/v1/authentication/qr/mobile_to_web/request",
      "https://ru.public.express/api/v1/authentication/register_confirm/qr",
      "https://cts.synthetic.invalid:8443/api/v1/ad_integration/register_confirm/qr",
    ]);
    expect(
      JSON.parse(fetchMock.mock.calls[2]![1]!.body as string),
    ).toEqual({
      registration_id: "synthetic-mobile-registration",
      temp_token: "synthetic-rts-temp-token",
    });
    expect(
      JSON.parse(fetchMock.mock.calls[3]![1]!.body as string),
    ).toEqual({
      rts_registration_id: state.registrationId,
      temp_token: "synthetic-cts-temp-token",
      ets: false,
    });
    expect(session.rts).toMatchObject({
      host: "ru.public.express",
      authToken: "synthetic-rts-auth",
      userHuid: "synthetic-user",
    });
    expect(session.cts).toMatchObject({
      host: "cts.synthetic.invalid:8443",
      accessToken: "synthetic-cts-auth",
      refreshToken: "synthetic-cts-refresh",
      userHuid: "synthetic-user",
      active: true,
    });
    expect(session.encryptionKeys).toEqual(transferred);
    expect(session.device.udid).toBe(state.udid);
    expect(session.device.signingKeyId).toBe(state.registrationId);
  });

  it("rejects a non-ok response without reflecting server or secret payloads", async () => {
    const state = await createQrRegistrationState();
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(
      jsonResponse({
        status: "error",
        reason: "synthetic_denied",
        sensitive_debug: "MUST_NOT_BE_REFLECTED",
      }),
    );

    await expect(
      completeQrRegistration({
        initialRtsHost: "ru.public.express",
        state,
        device: {
          device: "Desktop 3.72.37",
          deviceSoftware: "macOS",
          deviceHostname: null,
          manufacturer: "Apple",
          platform: "desktop",
          locale: "ru",
          timezone: "Europe/Moscow",
        },
        fetch: fetchMock,
      }),
    ).rejects.not.toThrow(/MUST_NOT_BE_REFLECTED|synthetic_denied/);
  });

  it("preserves the RTS session when CTS confirmation fails", async () => {
    await sodium.ready;
    const state = await createQrRegistrationState();
    const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
    const encryptedRegistrationData = sodium.to_base64(
      join(
        nonce,
        sodium.crypto_secretbox_easy(
          sodium.from_string(
            JSON.stringify({
              rts_host: "https://ru.public.express/",
              cts_host: "https://cts.synthetic.invalid/",
            }),
          ),
          nonce,
          state.registrationKey,
        ),
      ),
      sodium.base64_variants.ORIGINAL,
    );
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        jsonResponse({
          status: "ok",
          result: {
            registration_id: "synthetic-mobile-registration",
            registration_data: encryptedRegistrationData,
            rts_registration_token: "synthetic-rts-temp-token",
            cts_registration_token: "synthetic-cts-temp-token",
          },
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse({
          status: "ok",
          result: {
            auth_token: "synthetic-rts-auth",
            user_huid: "synthetic-user",
            server_id: "synthetic-rts-server",
          },
        }),
      )
      .mockResolvedValueOnce(new Response(null, { status: 500 }));

    const session = await completeQrRegistration({
      initialRtsHost: "ru.public.express",
      state,
      device: {
        device: "Desktop 3.72.37",
        deviceSoftware: "macOS",
        deviceHostname: "connector",
        manufacturer: "Apple",
        platform: "desktop",
        locale: "ru",
        timezone: "Europe/Moscow",
      },
      fetch: fetchMock,
    });

    expect(session.rts.authToken).toBe("synthetic-rts-auth");
    expect(session.cts).toBeUndefined();
    expect(session.ctsPending).toEqual({
      host: "cts.synthetic.invalid",
      temporaryToken: "synthetic-cts-temp-token",
    });
  });
});
