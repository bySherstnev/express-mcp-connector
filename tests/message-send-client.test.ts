import sodium from "libsodium-wrappers-sumo";
import { describe, expect, it } from "vitest";

import type { StandaloneExpressSession } from "../src/auth/standalone-qr-client.js";
import { decryptExpress372Payload } from "../src/crypto/express-372-decrypt.js";
import type { DeviceChat } from "../src/express/device-chat-list.js";
import {
  composeEncryptedTextEvent,
  MessageDeliveryError,
  sendSocketEvent,
} from "../src/express/message-send-client.js";

describe("eXpress encrypted message composition", () => {
  it("encrypts for chat recipients and signs the ciphertext", async () => {
    await sodium.ready;
    const sender = sodium.crypto_box_seed_keypair(
      Uint8Array.from({ length: sodium.crypto_box_SEEDBYTES }, (_, i) => i + 1),
    );
    const recipient = sodium.crypto_box_seed_keypair(
      Uint8Array.from({ length: sodium.crypto_box_SEEDBYTES }, (_, i) => i + 65),
    );
    const signing = sodium.crypto_sign_seed_keypair(
      Uint8Array.from({ length: sodium.crypto_sign_SEEDBYTES }, (_, i) => i + 129),
    );
    const session = {
      version: 1,
      createdAt: "2026-01-01T00:00:00.000Z",
      rts: {
        host: "synthetic.invalid",
        authToken: "SYNTHETIC_TOKEN",
        expiresAt: null,
        userHuid: "synthetic-sender",
        serverId: "synthetic-server",
      },
      cts: {
        host: "cts.synthetic.invalid",
        accessToken: "SYNTHETIC_CTS_TOKEN",
        refreshToken: "SYNTHETIC_CTS_REFRESH",
        expiresIn: 3600,
        userHuid: "synthetic-corporate-sender",
        serverId: "synthetic-cts-server",
        active: true,
      },
      device: {
        udid: "synthetic-udid",
        registrationId: "synthetic-registration",
        signingKeyId: "synthetic-registration-signing-id",
        signingAlgorithm: "ed25519",
        signingPublicKey: "SYNTHETIC_REGISTRATION_PUBLIC",
        signingPrivateKey: "SYNTHETIC_REGISTRATION_PRIVATE",
      },
      requestSigning: {
        publicKeyId: "synthetic-signing-id",
        privateKeyId: "synthetic-signing-private-id",
        algorithm: signing.keyType,
        publicKey: sodium.to_base64(
          signing.publicKey,
          sodium.base64_variants.ORIGINAL,
        ),
        privateKey: sodium.to_base64(
          signing.privateKey,
          sodium.base64_variants.ORIGINAL,
        ),
        uploaded: true,
        uploadedConnections: ["cts"],
      },
      encryptionKeys: {
        cts_pub_key_id: "synthetic-sender-key",
        cts_pub_key_body: sodium.to_base64(
          sender.publicKey,
          sodium.base64_variants.ORIGINAL,
        ),
        cts_priv_key_body: sodium.to_base64(
          sender.privateKey,
          sodium.base64_variants.ORIGINAL,
        ),
        cts_key_algo: "xsalsa20:xchacha20_aead_ietf",
      },
    } satisfies StandaloneExpressSession;
    const chat: DeviceChat = {
      connection: "cts",
      groupChatId: "synthetic-chat-id",
      name: "Synthetic chat",
      chatType: "group_chat",
      encryptionKeyIds: ["synthetic-recipient-key"],
      encryptionAlgorithm: "xsalsa20:xchacha20_aead_ietf",
      active: true,
      left: false,
      sharedHistory: false,
      lastEventSyncId: null,
      lastEventInsertedAt: null,
      lastIgnoreMessagesAt: null,
    };
    const ids = [
      "00000000-0000-4000-8000-000000000001",
      "00000000-0000-4000-8000-000000000002",
    ];
    const event = await composeEncryptedTextEvent(
      session,
      chat,
      "Synthetic outbound message",
      new Map([
        [
          "synthetic-recipient-key",
          {
            id: "synthetic-recipient-key",
            body: sodium.to_base64(
              recipient.publicKey,
              sodium.base64_variants.ORIGINAL,
            ),
            kind: "curve25519",
            algo: "xsalsa20:xchacha20_aead_ietf",
            userHuid: "synthetic-recipient",
          },
        ],
      ]),
      {
        uuid: () => ids.shift()!,
        now: () => "2026-09-06T12:00:00.000Z",
        syncId: "00000000-0000-4000-8000-000000000009",
      },
    );

    const plaintext = await decryptExpress372Payload({
      encryptedEnvelope: event.keys[0]!.key,
      encryptedPayload: event.payload,
      recipientPrivateKey: recipient.privateKey,
      senderPublicKey: sender.publicKey,
      groupChatId: event.group_chat_id,
      syncId: event.sync_id,
    });
    expect(plaintext).toMatchObject({
      type: "text",
      from: "synthetic-corporate-sender",
      body: "Synthetic outbound message",
      group_chat_id: "synthetic-chat-id",
    });
    expect(event.sync_id).toBe("00000000-0000-4000-8000-000000000009");
    expect(
      sodium.crypto_sign_verify_detached(
        sodium.from_base64(
          event.signature.sign,
          sodium.base64_variants.ORIGINAL,
        ),
        event.payload,
        signing.publicKey,
      ),
    ).toBe(true);

    await expect(composeEncryptedTextEvent(
      session,
      { ...chat, encryptionAlgorithm: "future-chat-profile" },
      "must fail closed",
      new Map(),
    )).rejects.toThrow(/unsupported.*chat encryption profile/i);
    await expect(composeEncryptedTextEvent(
      {
        ...session,
        encryptionKeys: { ...session.encryptionKeys, cts_key_algo: "future-device" },
      },
      chat,
      "must fail closed",
      new Map(),
    )).rejects.toThrow(/unsupported.*device encryption algorithm/i);
    await expect(composeEncryptedTextEvent(
      {
        ...session,
        requestSigning: { ...session.requestSigning, algorithm: "future-signature" },
      },
      chat,
      "must fail closed",
      new Map(),
    )).rejects.toThrow(/unsupported.*signing algorithm/i);
    await expect(composeEncryptedTextEvent(
      session,
      chat,
      "must fail closed",
      new Map([[
        "synthetic-recipient-key",
        {
          id: "synthetic-recipient-key",
          body: sodium.to_base64(
            recipient.publicKey,
            sodium.base64_variants.ORIGINAL,
          ),
          kind: "curve25519",
          algo: "future-recipient",
          userHuid: "synthetic-recipient",
        },
      ]]),
    )).rejects.toThrow(/recipient uses an unsupported encryption algorithm/i);
  });

  it("maps the observed legacy chat profile to the authenticated event envelope", async () => {
    await sodium.ready;
    const sender = sodium.crypto_box_keypair();
    const recipient = sodium.crypto_box_keypair();
    const signing = sodium.crypto_sign_keypair();
    const session = {
      version: 1,
      createdAt: "2026-01-01T00:00:00.000Z",
      rts: {
        host: "synthetic.invalid",
        authToken: "SYNTHETIC_TOKEN",
        expiresAt: null,
        userHuid: "synthetic-sender",
        serverId: "synthetic-server",
      },
      cts: {
        host: "cts.synthetic.invalid",
        accessToken: "SYNTHETIC_CTS_TOKEN",
        refreshToken: null,
        expiresIn: 0,
        expiresAt: null,
        userHuid: "synthetic-sender",
        serverId: "synthetic-cts",
        active: true,
      },
      device: {
        udid: "synthetic-udid",
        registrationId: "synthetic-registration",
        signingKeyId: "synthetic-registration",
        signingAlgorithm: "ed25519",
        signingPublicKey: "SYNTHETIC_REGISTRATION_PUBLIC",
        signingPrivateKey: "SYNTHETIC_REGISTRATION_PRIVATE",
      },
      requestSigning: {
        publicKeyId: "synthetic-signing-id",
        privateKeyId: "synthetic-signing-private-id",
        algorithm: signing.keyType,
        publicKey: sodium.to_base64(
          signing.publicKey,
          sodium.base64_variants.ORIGINAL,
        ),
        privateKey: sodium.to_base64(
          signing.privateKey,
          sodium.base64_variants.ORIGINAL,
        ),
        uploaded: true,
        uploadedConnections: ["cts"],
      },
      encryptionKeys: {
        cts_key_algo: "xsalsa20",
        cts_pub_key_id: "synthetic-own-key",
        cts_pub_key_body: sodium.to_base64(
          sender.publicKey,
          sodium.base64_variants.ORIGINAL,
        ),
        cts_priv_key_body: sodium.to_base64(
          sender.privateKey,
          sodium.base64_variants.ORIGINAL,
        ),
      },
    } satisfies StandaloneExpressSession;
    const chat: DeviceChat = {
      connection: "cts",
      groupChatId: "synthetic-chat-id",
      name: "Synthetic shared chat",
      chatType: "group_chat",
      encryptionKeyIds: ["synthetic-recipient-key"],
      encryptionAlgorithm: "xsalsa20:chacha20",
      active: true,
      left: false,
      sharedHistory: true,
      lastEventSyncId: null,
      lastEventInsertedAt: null,
      lastIgnoreMessagesAt: null,
    };
    const event = await composeEncryptedTextEvent(
      session,
      chat,
      "Synthetic shared message",
      new Map([
        [
          "synthetic-recipient-key",
          {
            id: "synthetic-recipient-key",
            body: sodium.to_base64(
              recipient.publicKey,
              sodium.base64_variants.ORIGINAL,
            ),
            kind: "cts",
            algo: "xsalsa20",
            userHuid: "synthetic-recipient",
          },
        ],
      ]),
    );
    expect(event.keys).toHaveLength(1);
    expect(event.keys[0]!.algo).toBe("xsalsa20:xchacha20_aead_ietf");
    await expect(decryptExpress372Payload({
      encryptedEnvelope: event.keys[0]!.key,
      encryptedPayload: event.payload,
      recipientPrivateKey: recipient.privateKey,
      senderPublicKey: sender.publicKey,
      groupChatId: event.group_chat_id,
      syncId: event.sync_id,
    })).resolves.toMatchObject({
      type: "text",
      body: "Synthetic shared message",
      group_chat_id: "synthetic-chat-id",
    });
  });

  it("classifies a malformed post-dispatch acknowledgement as unknown", async () => {
    class MalformedAcknowledgementSocket extends EventTarget {
      constructor() {
        super();
        queueMicrotask(() => this.dispatchEvent(new Event("open")));
      }

      send(data: string): void {
        const request = JSON.parse(data) as { ref: number };
        const response = request.ref === 0
          ? { ref: 0, payload: { status: "ok" } }
          : { ref: 1, payload: {} };
        queueMicrotask(() => this.dispatchEvent(new MessageEvent("message", {
          data: JSON.stringify(response),
        })));
      }

      close(): void {}
    }
    const session = {
      ...({} as StandaloneExpressSession),
      rts: {
        host: "synthetic.invalid",
        authToken: "SYNTHETIC_TOKEN",
        expiresAt: null,
        userHuid: "synthetic-user",
        serverId: "synthetic-server",
      },
      encryptionKeys: { rts_pub_key_id: "synthetic-key" },
    };
    const event = {
      group_chat_id: "synthetic-chat",
      sync_id: "synthetic-sync",
      payload: "SYNTHETIC_PAYLOAD",
      keys: [],
      signature: {
        sign: "SYNTHETIC_SIGNATURE",
        sign_key_id: "synthetic-signing-key",
        sign_algo: "ed25519",
      },
    };

    await expect(sendSocketEvent(session, event, "rts", {
      socketFactory: () =>
        new MalformedAcknowledgementSocket() as unknown as WebSocket,
    })).rejects.toMatchObject({
      name: MessageDeliveryError.name,
      status: "unknown",
    });
  });
});
