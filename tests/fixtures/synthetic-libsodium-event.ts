import sodium from "libsodium-wrappers-sumo";

const GROUP_CHAT_ID = "synthetic-group-fixture";
const SYNC_ID = "synthetic-sync-fixture";

const EXPECTED_EVENT = {
  type: "message_new",
  body: "SYNTHETIC_TEST_MESSAGE_ONLY",
  group_chat_id: GROUP_CHAT_ID,
  sender: {
    displayName: "Synthetic Fixture User",
  },
};

function sequence(length: number, start: number): Uint8Array {
  return Uint8Array.from({ length }, (_, index) => (start + index) % 256);
}

function join(left: Uint8Array, right: Uint8Array): Uint8Array {
  const result = new Uint8Array(left.length + right.length);
  result.set(left);
  result.set(right, left.length);
  return result;
}

/**
 * Builds a deterministic, entirely synthetic eXpress 3.72-compatible fixture.
 * The constants below are test material only and are not copied from a device.
 */
export async function createSyntheticLibsodiumEventFixture(
  plaintextOverrides: Record<string, unknown> = {},
) {
  await sodium.ready;

  const sender = sodium.crypto_box_seed_keypair(sequence(sodium.crypto_box_SEEDBYTES, 1));
  const recipient = sodium.crypto_box_seed_keypair(sequence(sodium.crypto_box_SEEDBYTES, 65));
  const contentKey = sequence(sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES, 129);
  const envelopeNonce = sequence(sodium.crypto_box_NONCEBYTES, 17);
  const payloadNonce = sequence(
    sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
    193,
  );

  const envelopeCiphertext = sodium.crypto_box_easy(
    contentKey,
    envelopeNonce,
    recipient.publicKey,
    sender.privateKey,
  );

  const associatedData = sodium.from_string(`${GROUP_CHAT_ID}:${SYNC_ID}`);
  const expectedEvent = { ...EXPECTED_EVENT, ...plaintextOverrides };
  const plaintext = sodium.from_string(JSON.stringify(expectedEvent));
  const payloadCiphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    plaintext,
    associatedData,
    null,
    payloadNonce,
    contentKey,
  );

  return {
    groupChatId: GROUP_CHAT_ID,
    syncId: SYNC_ID,
    encryptedEnvelope: sodium.to_base64(
      join(envelopeNonce, envelopeCiphertext),
      sodium.base64_variants.ORIGINAL,
    ),
    encryptedPayload: sodium.to_base64(
      join(payloadNonce, payloadCiphertext),
      sodium.base64_variants.ORIGINAL,
    ),
    recipientPrivateKey: recipient.privateKey,
    senderPublicKey: sender.publicKey,
    expectedEvent,
  };
}
