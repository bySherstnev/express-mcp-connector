import { describe, expect, it, vi } from "vitest";
import sodium from "libsodium-wrappers-sumo";

import type { StandaloneExpressSession } from "../src/auth/standalone-qr-client.js";
import {
  buildUploadSigningKeyRequest,
  fetchRtsServerPublicKey,
  prepareRtsRequestIdentity,
  uploadRtsRequestIdentity,
  uploadCtsRequestIdentity,
} from "../src/auth/rts-session-bootstrap.js";

function sessionFixture(boxKeys: sodium.KeyPair): StandaloneExpressSession {
  return {
    version: 1,
    createdAt: "2026-09-06T00:00:00.000Z",
    rts: {
      host: "rts.synthetic.invalid",
      authToken: "synthetic-auth-token",
      expiresAt: null,
      userHuid: "synthetic-user",
      serverId: "synthetic-server",
    },
    device: {
      udid: "synthetic-udid",
      registrationId: "synthetic-registration",
      signingKeyId: "synthetic-registration-signing-id",
      signingAlgorithm: "ed25519",
      signingPublicKey: "synthetic-registration-public",
      signingPrivateKey: "synthetic-registration-private",
    },
    cts: {
      host: "cts.synthetic.invalid",
      accessToken: "synthetic-cts-token",
      refreshToken: null,
      expiresIn: 3600,
      userHuid: "synthetic-user",
      serverId: "synthetic-cts-server",
      active: true,
    },
    encryptionKeys: {
      rts_key_algo: "xsalsa20",
      rts_pub_key_id: "synthetic-rts-public-id",
      cts_key_algo: "xsalsa20",
      rts_priv_key_body: sodium.to_base64(
        boxKeys.privateKey,
        sodium.base64_variants.ORIGINAL,
      ),
    },
  };
}

describe("RTS session bootstrap", () => {
  it("persists one request identity, loads KDC key, and uploads its public half", async () => {
    await sodium.ready;
    const clientBox = sodium.crypto_box_keypair();
    const serverBox = sodium.crypto_box_keypair();
    const initial = sessionFixture(clientBox);
    const prepared = await prepareRtsRequestIdentity(initial);
    expect(prepared.requestSigning?.uploaded).toBe(false);
    expect(await prepareRtsRequestIdentity(prepared)).toBe(prepared);

    const kdcFetch = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(
        JSON.stringify({
          status: "ok",
          result: sodium.to_base64(
            serverBox.publicKey,
            sodium.base64_variants.ORIGINAL,
          ),
        }),
        { status: 200 },
      ),
    );
    const withServerKey = await fetchRtsServerPublicKey(prepared, kdcFetch);
    const request = await buildUploadSigningKeyRequest(withServerKey);
    expect(request.url).toBe(
      "https://rts.synthetic.invalid/api/v2/kdc/keys/synthetic-user",
    );
    expect(JSON.parse(request.body)).toEqual({
      key: prepared.requestSigning?.publicKey,
      kind: "ed25519",
      algo: "xsalsa20",
      id: prepared.requestSigning?.publicKeyId,
    });
    expect(request.headers.Authorization).toBe("Bearer synthetic-auth-token");

    const uploadFetch = vi.fn<typeof fetch>().mockImplementation(async () =>
      new Response(JSON.stringify({ status: "ok", result: {} }), {
        status: 200,
      }),
    );
    const uploaded = await uploadRtsRequestIdentity(
      withServerKey,
      uploadFetch,
    );
    expect(uploaded.requestSigning?.uploaded).toBe(true);

    const ctsRequest = await buildUploadSigningKeyRequest(prepared, "cts");
    expect(ctsRequest.url).toBe(
      "https://cts.synthetic.invalid/api/v2/kdc/keys/synthetic-user",
    );
    expect(ctsRequest.headers.Authorization).toBe("Bearer synthetic-cts-token");
    const ctsUploaded = await uploadCtsRequestIdentity(prepared, uploadFetch);
    expect(ctsUploaded.requestSigning?.uploaded).toBe(true);
  });
});
