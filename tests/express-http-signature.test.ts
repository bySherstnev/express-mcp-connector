import { describe, expect, it } from "vitest";
import sodium from "libsodium-wrappers-sumo";

import { signExpressRequest } from "../src/auth/express-http-signature.js";

describe("eXpress HTTP signature", () => {
  it("matches the 3.72 request-target, nonce, created and digest contract", async () => {
    await sodium.ready;
    const keys = sodium.crypto_sign_seed_keypair(
      Uint8Array.from({ length: sodium.crypto_sign_SEEDBYTES }, (_, i) => i + 1),
    );
    const nonce = Uint8Array.from({ length: 32 }, (_, i) => 200 - i);
    const body = JSON.stringify({ registration_id: "synthetic-registration" });

    const signed = signExpressRequest({
      method: "POST",
      target: "/api/v1/authentication/qr/mobile_to_web/request",
      body,
      keyId: "synthetic-registration",
      algorithm: "ed25519",
      privateKey: keys.privateKey,
      created: 1_700_000_001,
      nonce,
    });

    const nonceBase64 = sodium.to_base64(nonce, sodium.base64_variants.ORIGINAL);
    const digest = sodium.to_base64(
      sodium.crypto_hash_sha256(sodium.from_string(body)),
      sodium.base64_variants.ORIGINAL,
    );
    expect(signed.signatureData).toBe(
      `(request-target): post /api/v1/authentication/qr/mobile_to_web/request\n` +
        `(created): 1700000001\n` +
        `express-request-nonce: ${nonceBase64}\n` +
        `digest: SHA-256=${digest}`,
    );
    expect(signed.headers["Express-Request-Nonce"]).toBe(nonceBase64);
    expect(signed.headers.Digest).toBe(`SHA-256=${digest}`);
    expect(signed.headers["Content-Type"]).toBe("application/json");

    const signature = /signature="([^"]+)"/.exec(signed.headers.Signature)?.[1];
    expect(signature).toBeTruthy();
    expect(
      sodium.crypto_sign_verify_detached(
        sodium.from_base64(signature!, sodium.base64_variants.ORIGINAL),
        signed.signatureData,
        keys.publicKey,
      ),
    ).toBe(true);
  });
});
