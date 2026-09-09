import { describe, expect, it } from "vitest";
import sodium from "libsodium-wrappers-sumo";

import {
  buildMobileToWebRegistrationRequest,
  createQrRegistrationState,
  decryptQrRegistrationData,
  serializeQrPayload,
} from "../src/auth/standalone-qr-registration.js";

function join(left: Uint8Array, right: Uint8Array): Uint8Array {
  const result = new Uint8Array(left.length + right.length);
  result.set(left);
  result.set(right, left.length);
  return result;
}

describe("standalone eXpress 3.72 QR registration", () => {
  it("serializes only the public QR bootstrap fields", async () => {
    const state = await createQrRegistrationState({
      randomUuid: (() => {
        const values = ["synthetic-registration", "synthetic-sign-key", "synthetic-udid"];
        return () => values.shift()!;
      })(),
      randomBytes: (length) => Uint8Array.from({ length }, (_, i) => i + 1),
    });

    expect(JSON.parse(serializeQrPayload(state))).toEqual({
      registration_id: "synthetic-registration",
      registration_key: sodium.to_base64(
        state.registrationKey,
        sodium.base64_variants.ORIGINAL,
      ),
      registration_token: sodium.to_base64(
        Uint8Array.from({ length: 64 }, (_, i) => i + 1),
        sodium.base64_variants.ORIGINAL,
      ),
      version: 1,
    });
    expect(serializeQrPayload(state)).not.toContain(
      sodium.to_base64(state.signingPrivateKey, sodium.base64_variants.ORIGINAL),
    );
  });

  it("builds the signed mobile-to-web long-poll request", async () => {
    const state = await createQrRegistrationState();
    const request = buildMobileToWebRegistrationRequest({
      rtsHost: "ru.public.express",
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
      created: 1_700_000_002,
      signatureNonce: Uint8Array.from({ length: 32 }, () => 7),
    });

    expect(request.method).toBe("POST");
    expect(request.url).toBe(
      "https://ru.public.express/api/v1/authentication/qr/mobile_to_web/request",
    );
    expect(JSON.parse(request.body)).toMatchObject({
      registration_id: state.registrationId,
      registration_token: state.registrationToken,
      sign_pub_key: sodium.to_base64(
        state.signingPublicKey,
        sodium.base64_variants.ORIGINAL,
      ),
      udid: state.udid,
      app_version: "3.72.37",
      platform_package_id: "ru.unlimitedtech.express.desktop",
      device_meta: { pushes: false, permissions: {} },
    });
    expect(request.headers.Signature).toContain(`keyId="${state.registrationId}"`);
    expect(request.headers["Accept-Language"]).toBe("ru");
    expect(request.headers["User-Agent"]).toContain("eXpress/3.72.37");
  });

  it("decrypts registration data transferred by the authorized mobile device", async () => {
    await sodium.ready;
    const key = Uint8Array.from(
      { length: sodium.crypto_secretbox_KEYBYTES },
      (_, i) => i + 10,
    );
    const nonce = Uint8Array.from(
      { length: sodium.crypto_secretbox_NONCEBYTES },
      (_, i) => i + 80,
    );
    const expected = {
      rts_host: "synthetic-rts.invalid",
      cts_host: "synthetic-cts.invalid",
      phone: "+00000000000",
      rts_pub_key_id: "synthetic-public-key",
      rts_priv_key_id: "synthetic-private-key",
    };
    const encrypted = sodium.crypto_secretbox_easy(
      sodium.from_string(JSON.stringify(expected)),
      nonce,
      key,
    );
    const encoded = sodium.to_base64(
      join(nonce, encrypted),
      sodium.base64_variants.ORIGINAL,
    );

    await expect(decryptQrRegistrationData(encoded, key)).resolves.toEqual(expected);
    await expect(
      decryptQrRegistrationData(encoded, Uint8Array.from(key, (byte) => byte ^ 0xff)),
    ).rejects.toThrow(/decrypt|authenticate/i);
  });
});
