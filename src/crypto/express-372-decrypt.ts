import sodium from "libsodium-wrappers-sumo";

export interface Express372EncryptedPayload {
  encryptedEnvelope: string;
  encryptedPayload: string;
  recipientPrivateKey: Uint8Array;
  senderPublicKey: Uint8Array;
  groupChatId: string;
  syncId: string;
}

function requireNonEmpty(value: string, field: string): void {
  if (value.length === 0) {
    throw new TypeError(`${field} must be a non-empty string`);
  }
}

function decodeBase64(value: string, field: string): Uint8Array {
  requireNonEmpty(value, field);

  try {
    return sodium.from_base64(value, sodium.base64_variants.ORIGINAL);
  } catch {
    throw new Error(`${field} is not valid base64`);
  }
}

function splitNonce(
  value: Uint8Array,
  nonceLength: number,
  field: string,
): [nonce: Uint8Array, ciphertext: Uint8Array] {
  if (value.length <= nonceLength) {
    throw new Error(`${field} has an invalid encrypted frame`);
  }

  return [value.subarray(0, nonceLength), value.subarray(nonceLength)];
}

/**
 * Opens a non-shared eXpress 3.72 event envelope and its authenticated JSON
 * payload. Errors are deliberately sanitized so encrypted or plaintext data is
 * never reflected to callers or logs.
 */
export async function decryptExpress372Payload(
  input: Express372EncryptedPayload,
): Promise<unknown> {
  await sodium.ready;

  requireNonEmpty(input.groupChatId, "groupChatId");
  requireNonEmpty(input.syncId, "syncId");

  if (input.recipientPrivateKey.length !== sodium.crypto_box_SECRETKEYBYTES) {
    throw new Error("recipientPrivateKey has an invalid length");
  }

  if (input.senderPublicKey.length !== sodium.crypto_box_PUBLICKEYBYTES) {
    throw new Error("senderPublicKey has an invalid length");
  }

  const [envelopeNonce, envelopeCiphertext] = splitNonce(
    decodeBase64(input.encryptedEnvelope, "encryptedEnvelope"),
    sodium.crypto_box_NONCEBYTES,
    "encryptedEnvelope",
  );

  let contentKey: Uint8Array;
  try {
    contentKey = sodium.crypto_box_open_easy(
      envelopeCiphertext,
      envelopeNonce,
      input.senderPublicKey,
      input.recipientPrivateKey,
    );
  } catch {
    throw new Error("Unable to decrypt or authenticate the event envelope");
  }

  let plaintext: Uint8Array | undefined;
  try {
    if (contentKey.length !== sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
      throw new Error("Decrypted event key has an invalid length");
    }
    const [payloadNonce, payloadCiphertext] = splitNonce(
      decodeBase64(input.encryptedPayload, "encryptedPayload"),
      sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
      "encryptedPayload",
    );
    const associatedData = sodium.from_string(
      `${input.groupChatId}:${input.syncId}`,
    );

    plaintext = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      payloadCiphertext,
      associatedData,
      payloadNonce,
      contentKey,
    );
    try {
      return JSON.parse(sodium.to_string(plaintext)) as unknown;
    } catch {
      throw new Error("Decrypted event payload is not valid JSON");
    }
  } catch (error) {
    if (
      error instanceof Error &&
      (error.message === "encryptedPayload is not valid base64" ||
        error.message === "encryptedPayload has an invalid encrypted frame" ||
        error.message === "Decrypted event key has an invalid length" ||
        error.message === "Decrypted event payload is not valid JSON")
    ) {
      throw error;
    }

    throw new Error("Unable to decrypt or authenticate the event payload");
  } finally {
    sodium.memzero(contentKey);
    if (plaintext !== undefined) {
      sodium.memzero(plaintext);
    }
  }
}
