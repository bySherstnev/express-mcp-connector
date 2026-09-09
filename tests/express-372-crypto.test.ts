import { describe, expect, it } from "vitest";

import { decryptExpress372Payload } from "../src/crypto/express-372-decrypt.js";
import { createSyntheticLibsodiumEventFixture } from "./fixtures/synthetic-libsodium-event.js";

describe("eXpress Desktop 3.72 crypto compatibility", () => {
  it("opens the crypto_box envelope and XChaCha20-Poly1305 JSON payload", async () => {
    const fixture = await createSyntheticLibsodiumEventFixture();

    const event = await decryptExpress372Payload({
      encryptedEnvelope: fixture.encryptedEnvelope,
      encryptedPayload: fixture.encryptedPayload,
      recipientPrivateKey: fixture.recipientPrivateKey,
      senderPublicKey: fixture.senderPublicKey,
      groupChatId: fixture.groupChatId,
      syncId: fixture.syncId,
    });

    expect(event).toEqual(fixture.expectedEvent);
  });

  it("fails authentication when syncId does not match the AEAD associated data", async () => {
    const fixture = await createSyntheticLibsodiumEventFixture();

    await expect(
      decryptExpress372Payload({
        encryptedEnvelope: fixture.encryptedEnvelope,
        encryptedPayload: fixture.encryptedPayload,
        recipientPrivateKey: fixture.recipientPrivateKey,
        senderPublicKey: fixture.senderPublicKey,
        groupChatId: fixture.groupChatId,
        syncId: "synthetic-wrong-sync",
      }),
    ).rejects.toThrow(/decrypt|authentication|cipher|associated data/i);
  });
});
