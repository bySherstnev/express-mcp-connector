import sodium from "libsodium-wrappers-sumo";
import { describe, expect, it, vi } from "vitest";

import type { StandaloneExpressSession } from "../src/auth/standalone-qr-client.js";
import type { DeviceChat } from "../src/express/device-chat-list.js";
import {
  decryptHistoryEvents,
  readDecryptedHistory,
} from "../src/express/decrypted-history.js";
import type { ExpressPublicKey } from "../src/express/kdc-public-keys.js";
import { createSyntheticLibsodiumEventFixture } from "./fixtures/synthetic-libsodium-event.js";

describe("decrypted history normalization", () => {
  it("returns useful message fields without raw cryptographic material", async () => {
    const fixture = await createSyntheticLibsodiumEventFixture();
    await sodium.ready;
    const session = {
      version: 1,
      createdAt: "2026-01-01T00:00:00.000Z",
      rts: {
        host: "synthetic.invalid",
        authToken: "SYNTHETIC_TOKEN",
        expiresAt: null,
        userHuid: "recipient-user",
        serverId: "synthetic-server",
      },
      cts: {
        host: "cts.synthetic.invalid",
        accessToken: "SYNTHETIC_CTS_TOKEN",
        refreshToken: null,
        expiresIn: 3600,
        userHuid: "recipient-user",
        serverId: "synthetic-cts-server",
        active: true,
      },
      device: {
        udid: "synthetic-udid",
        registrationId: "synthetic-registration",
        signingKeyId: "synthetic-signing-id",
        signingAlgorithm: "ed25519",
        signingPublicKey: "SYNTHETIC_SIGNING_PUBLIC",
        signingPrivateKey: "SYNTHETIC_SIGNING_PRIVATE",
      },
      encryptionKeys: {
        cts_priv_key_body: sodium.to_base64(
          fixture.recipientPrivateKey,
          sodium.base64_variants.ORIGINAL,
        ),
      },
    } satisfies StandaloneExpressSession;
    const chat: DeviceChat = {
      connection: "cts",
      groupChatId: fixture.groupChatId,
      name: "Synthetic chat",
      chatType: "group_chat",
      encryptionKeyIds: [],
      encryptionAlgorithm: null,
      active: true,
      left: false,
      sharedHistory: true,
      lastEventSyncId: fixture.syncId,
      lastEventInsertedAt: "2026-09-06T12:00:00.000Z",
      lastIgnoreMessagesAt: null,
    };
    const key: ExpressPublicKey = {
      id: "synthetic-sender-key",
      body: sodium.to_base64(
        fixture.senderPublicKey,
        sodium.base64_variants.ORIGINAL,
      ),
      kind: "curve25519",
      algo: "xsalsa20:xchacha20_aead_ietf",
      userHuid: "synthetic-sender",
    };
    const result = await decryptHistoryEvents(
      session,
      chat,
      {
        generatedAt: "2026-09-06T12:01:00.000Z",
        events: [
          {
            event_type: "message_new",
            group_chat_id: fixture.groupChatId,
            sync_id: fixture.syncId,
            inserted_at: "2026-09-06T12:00:00.000Z",
            sender_key_id: key.id,
            key: {
              key: fixture.encryptedEnvelope,
              algo: key.algo,
            },
            payload: fixture.encryptedPayload,
          },
          {
            event_type: "message_new",
            group_chat_id: fixture.groupChatId,
            sync_id: "synthetic-deleted-sync",
            inserted_at: "2026-09-06T11:59:00.000Z",
            sender_key_id: key.id,
          },
        ],
      },
      new Map([[key.id, key]]),
    );

    expect(result.messages).toEqual([
      {
        syncId: fixture.syncId,
        eventType: "message_new",
        insertedAt: "2026-09-06T12:00:00.000Z",
        messageId: null,
        senderId: "synthetic-author",
        senderName: null,
        kind: "message_new",
        body: "SYNTHETIC_TEST_MESSAGE_ONLY",
        replyToMessageId: null,
        attachmentFileId: null,
        forwardedFrom: null,
        status: "decrypted",
      },
      {
        syncId: "synthetic-deleted-sync",
        eventType: "message_new",
        insertedAt: "2026-09-06T11:59:00.000Z",
        messageId: null,
        senderId: null,
        senderName: null,
        kind: null,
        body: null,
        replyToMessageId: null,
        attachmentFileId: null,
        forwardedFrom: null,
        status: "deleted",
      },
    ]);
    expect(JSON.stringify(result)).not.toContain(fixture.encryptedEnvelope);
    expect(JSON.stringify(result)).not.toContain(fixture.encryptedPayload);
    expect(result.unavailableCount).toBe(0);
  });

  it("keeps multiple payload authors that share one KDC transport key", async () => {
    const [fixture, secondFixture] = await Promise.all([
      createSyntheticLibsodiumEventFixture({ from: "first-author" }),
      createSyntheticLibsodiumEventFixture({ from: "second-author" }),
    ]);
    await sodium.ready;
    const session = {
      version: 1,
      createdAt: "2026-01-01T00:00:00.000Z",
      rts: {
        host: "synthetic.invalid",
        authToken: "SYNTHETIC_TOKEN",
        expiresAt: null,
        userHuid: "recipient-user",
        serverId: "synthetic-server",
      },
      device: {
        udid: "synthetic-udid",
        registrationId: "synthetic-registration",
        signingKeyId: "synthetic-signing-id",
        signingAlgorithm: "ed25519",
        signingPublicKey: "SYNTHETIC_SIGNING_PUBLIC",
        signingPrivateKey: "SYNTHETIC_SIGNING_PRIVATE",
      },
      encryptionKeys: {
        rts_priv_key_body: sodium.to_base64(
          fixture.recipientPrivateKey,
          sodium.base64_variants.ORIGINAL,
        ),
      },
    } satisfies StandaloneExpressSession;
    const chat: DeviceChat = {
      connection: "rts",
      groupChatId: fixture.groupChatId,
      name: "Synthetic chat",
      chatType: "group_chat",
      encryptionKeyIds: [],
      encryptionAlgorithm: null,
      active: true,
      left: false,
      sharedHistory: true,
      lastEventSyncId: fixture.syncId,
      lastEventInsertedAt: null,
      lastIgnoreMessagesAt: null,
    };
    const key: ExpressPublicKey = {
      id: "synthetic-sender-key",
      body: sodium.to_base64(
        fixture.senderPublicKey,
        sodium.base64_variants.ORIGINAL,
      ),
      kind: "curve25519",
      algo: "xsalsa20:xchacha20_aead_ietf",
      userHuid: "verified-kdc-user",
    };

    const result = await decryptHistoryEvents(
      session,
      chat,
      {
        generatedAt: null,
        events: [
          {
            event_type: "message_new",
            group_chat_id: fixture.groupChatId,
            sync_id: fixture.syncId,
            sender_key_id: key.id,
            key: {
              key: fixture.encryptedEnvelope,
              algo: "xsalsa20:xchacha20_aead_ietf",
            },
            payload: fixture.encryptedPayload,
          },
          {
            event_type: "message_new",
            group_chat_id: secondFixture.groupChatId,
            sync_id: secondFixture.syncId,
            sender_key_id: key.id,
            key: {
              key: secondFixture.encryptedEnvelope,
              algo: "xsalsa20:xchacha20_aead_ietf",
            },
            payload: secondFixture.encryptedPayload,
          },
        ],
      },
      new Map([[key.id, key]]),
    );

    expect(result.messages.map(({ senderId, senderName }) => ({
      senderId,
      senderName,
    }))).toEqual([
      { senderId: "first-author", senderName: null },
      { senderId: "second-author", senderName: null },
    ]);
  });

  it("resolves the authenticated payload author through the selected directory", async () => {
    const fixture = await createSyntheticLibsodiumEventFixture({
      from: "corporate-author",
      forward: {
        group_chat_id: "source-chat",
        sync_id: "source-message",
        sender_huid: "original-author",
        sender_conn_type: "cts",
        inserted_at: "2026-09-15T11:29:01.492Z",
        source_name: "Source chat",
        stealth: null,
      },
    });
    await sodium.ready;
    const session = {
      version: 1,
      createdAt: "2026-01-01T00:00:00.000Z",
      rts: {
        host: "synthetic.invalid",
        authToken: "SYNTHETIC_TOKEN",
        expiresAt: null,
        userHuid: "recipient-user",
        serverId: "synthetic-server",
      },
      cts: {
        host: "cts.synthetic.invalid",
        accessToken: "SYNTHETIC_CTS_TOKEN",
        refreshToken: null,
        expiresIn: 3600,
        expiresAt: null,
        userHuid: "recipient-user",
        serverId: "synthetic-cts-server",
        active: true,
      },
      device: {
        udid: "synthetic-udid",
        registrationId: "synthetic-registration",
        signingKeyId: "synthetic-signing-id",
        signingAlgorithm: "ed25519",
        signingPublicKey: "SYNTHETIC_SIGNING_PUBLIC",
        signingPrivateKey: "SYNTHETIC_SIGNING_PRIVATE",
      },
      encryptionKeys: {
        cts_priv_key_body: sodium.to_base64(
          fixture.recipientPrivateKey,
          sodium.base64_variants.ORIGINAL,
        ),
      },
    } satisfies StandaloneExpressSession;
    const chat: DeviceChat = {
      connection: "cts",
      groupChatId: fixture.groupChatId,
      name: "Synthetic chat",
      chatType: "group_chat",
      encryptionKeyIds: [],
      encryptionAlgorithm: null,
      active: true,
      left: false,
      sharedHistory: true,
      lastEventSyncId: fixture.syncId,
      lastEventInsertedAt: null,
      lastIgnoreMessagesAt: null,
    };
    const key: ExpressPublicKey = {
      id: "shared-transport-key",
      body: sodium.to_base64(
        fixture.senderPublicKey,
        sodium.base64_variants.ORIGINAL,
      ),
      kind: "curve25519",
      algo: "xsalsa20:xchacha20_aead_ietf",
      userHuid: "transport-key-owner",
    };
    const fetchUserProfiles = vi.fn().mockResolvedValue(
      new Map([
        [
          "corporate-author",
          { userHuid: "corporate-author", name: "Corporate Author" },
        ],
        [
          "original-author",
          { userHuid: "original-author", name: "Original Author" },
        ],
      ]),
    );

    const result = await readDecryptedHistory(
      session,
      chat,
      { limit: 10, beforeSyncId: "newer-page-anchor" },
      {
        fetchHistoryPage: vi.fn().mockResolvedValue({
          generatedAt: null,
          events: [
            {
              event_type: "message_new",
              group_chat_id: fixture.groupChatId,
              sync_id: fixture.syncId,
              sender_key_id: key.id,
              key: { key: fixture.encryptedEnvelope, algo: key.algo },
              payload: fixture.encryptedPayload,
            },
          ],
        }),
        fetchKdcPublicKeys: vi.fn().mockResolvedValue(new Map([[key.id, key]])),
        fetchUserProfiles,
      },
    );

    expect(result.messages[0]).toMatchObject({
      senderId: "corporate-author",
      senderName: "Corporate Author",
      forwardedFrom: {
        hidden: false,
        senderId: "original-author",
        senderName: "Original Author",
        connection: "cts",
        chatId: "source-chat",
        chatName: "Source chat",
        messageSyncId: "source-message",
        insertedAt: "2026-09-15T11:29:01.492Z",
      },
    });
    expect(fetchUserProfiles).toHaveBeenCalledWith(
      session,
      ["corporate-author", "original-author"],
      expect.objectContaining({ connection: "cts" }),
    );
  });

  it("does not expose or resolve hidden forwarding metadata", async () => {
    const fixture = await createSyntheticLibsodiumEventFixture({
      from: "visible-author",
      forward: {
        group_chat_id: "hidden-source-chat",
        sync_id: "hidden-source-message",
        sender_huid: "hidden-original-author",
        sender_conn_type: "cts",
        source_name: "Hidden source chat",
        stealth: true,
      },
    });
    await sodium.ready;
    const session = {
      rts: {
        host: "synthetic.invalid",
        authToken: "SYNTHETIC_TOKEN",
        userHuid: "recipient-user",
        serverId: "synthetic-server",
      },
      encryptionKeys: {
        rts_priv_key_body: sodium.to_base64(
          fixture.recipientPrivateKey,
          sodium.base64_variants.ORIGINAL,
        ),
      },
    } as StandaloneExpressSession;
    const chat = {
      connection: "rts",
      groupChatId: fixture.groupChatId,
      name: "Synthetic chat",
      chatType: "group_chat",
      encryptionKeyIds: [],
      encryptionAlgorithm: null,
      active: true,
      left: false,
      sharedHistory: true,
      lastEventSyncId: fixture.syncId,
      lastEventInsertedAt: null,
      lastIgnoreMessagesAt: null,
    } satisfies DeviceChat;
    const key = {
      id: "shared-transport-key",
      body: sodium.to_base64(
        fixture.senderPublicKey,
        sodium.base64_variants.ORIGINAL,
      ),
      kind: "curve25519",
      algo: "xsalsa20:xchacha20_aead_ietf",
      userHuid: "transport-key-owner",
    } satisfies ExpressPublicKey;

    const result = await decryptHistoryEvents(
      session,
      chat,
      {
        generatedAt: null,
        events: [
          {
            event_type: "message_new",
            group_chat_id: fixture.groupChatId,
            sync_id: fixture.syncId,
            sender_key_id: key.id,
            key: { key: fixture.encryptedEnvelope, algo: key.algo },
            payload: fixture.encryptedPayload,
          },
        ],
      },
      new Map([[key.id, key]]),
    );

    expect(result.messages[0]?.forwardedFrom).toEqual({
      hidden: true,
      senderId: null,
      senderName: null,
      connection: null,
      chatId: null,
      chatName: null,
      messageSyncId: null,
      insertedAt: null,
    });
    expect(JSON.stringify(result)).not.toContain("hidden-original-author");
    expect(JSON.stringify(result)).not.toContain("Hidden source chat");
  });

  it("keeps the HUID and a null name when directory resolution fails", async () => {
    const fixture = await createSyntheticLibsodiumEventFixture({
      from: "unresolved-author",
    });
    await sodium.ready;
    const session = {
      version: 1,
      createdAt: "2026-01-01T00:00:00.000Z",
      rts: {
        host: "synthetic.invalid",
        authToken: "SYNTHETIC_TOKEN",
        expiresAt: null,
        userHuid: "recipient-user",
        serverId: "synthetic-server",
      },
      device: {
        udid: "synthetic-udid",
        registrationId: "synthetic-registration",
        signingKeyId: "synthetic-signing-id",
        signingAlgorithm: "ed25519",
        signingPublicKey: "SYNTHETIC_SIGNING_PUBLIC",
        signingPrivateKey: "SYNTHETIC_SIGNING_PRIVATE",
      },
      encryptionKeys: {
        rts_priv_key_body: sodium.to_base64(
          fixture.recipientPrivateKey,
          sodium.base64_variants.ORIGINAL,
        ),
      },
    } satisfies StandaloneExpressSession;
    const chat: DeviceChat = {
      connection: "rts",
      groupChatId: fixture.groupChatId,
      name: "Synthetic chat",
      chatType: "group_chat",
      encryptionKeyIds: [],
      encryptionAlgorithm: null,
      active: true,
      left: false,
      sharedHistory: true,
      lastEventSyncId: fixture.syncId,
      lastEventInsertedAt: null,
      lastIgnoreMessagesAt: null,
    };
    const key: ExpressPublicKey = {
      id: "shared-transport-key",
      body: sodium.to_base64(
        fixture.senderPublicKey,
        sodium.base64_variants.ORIGINAL,
      ),
      kind: "curve25519",
      algo: "xsalsa20:xchacha20_aead_ietf",
      userHuid: "transport-key-owner",
    };

    const result = await readDecryptedHistory(
      session,
      chat,
      { limit: 10, beforeSyncId: "newer-page-anchor" },
      {
        fetchHistoryPage: vi.fn().mockResolvedValue({
          generatedAt: null,
          events: [
            {
              event_type: "message_new",
              group_chat_id: fixture.groupChatId,
              sync_id: fixture.syncId,
              sender_key_id: key.id,
              key: { key: fixture.encryptedEnvelope, algo: key.algo },
              payload: fixture.encryptedPayload,
            },
          ],
        }),
        fetchKdcPublicKeys: vi.fn().mockResolvedValue(new Map([[key.id, key]])),
        fetchUserProfiles: vi.fn().mockRejectedValue(new Error("offline")),
      },
    );

    expect(result.messages[0]).toMatchObject({
      senderId: "unresolved-author",
      senderName: null,
    });
  });

  it("does not decrypt events with missing or unknown algorithm metadata", async () => {
    const fixture = await createSyntheticLibsodiumEventFixture();
    await sodium.ready;
    const session = {
      rts: {
        host: "synthetic.invalid",
        authToken: "SYNTHETIC_TOKEN",
        userHuid: "recipient-user",
        serverId: "synthetic-server",
      },
      encryptionKeys: {
        rts_priv_key_body: sodium.to_base64(
          fixture.recipientPrivateKey,
          sodium.base64_variants.ORIGINAL,
        ),
      },
    } as StandaloneExpressSession;
    const chat = {
      connection: "rts",
      groupChatId: fixture.groupChatId,
      name: "Synthetic chat",
      chatType: "group_chat",
      encryptionKeyIds: [],
      encryptionAlgorithm: null,
      active: true,
      left: false,
      sharedHistory: true,
      lastEventSyncId: fixture.syncId,
      lastEventInsertedAt: null,
      lastIgnoreMessagesAt: null,
    } satisfies DeviceChat;
    const key = {
      id: "synthetic-sender-key",
      body: sodium.to_base64(
        fixture.senderPublicKey,
        sodium.base64_variants.ORIGINAL,
      ),
      kind: "curve25519",
      algo: "xsalsa20:xchacha20_aead_ietf",
      userHuid: "synthetic-sender",
    } satisfies ExpressPublicKey;
    const baseEvent = {
      event_type: "message_new",
      group_chat_id: fixture.groupChatId,
      sender_key_id: key.id,
      payload: fixture.encryptedPayload,
    };

    const result = await decryptHistoryEvents(
      session,
      chat,
      {
        generatedAt: null,
        events: [
          {
            ...baseEvent,
            sync_id: "missing-algorithm",
            key: { key: fixture.encryptedEnvelope },
          },
          {
            ...baseEvent,
            sync_id: "future-algorithm",
            key: { key: fixture.encryptedEnvelope, algo: "future-envelope" },
          },
        ],
      },
      new Map([[key.id, key]]),
    );

    expect(result.messages.map(({ status }) => status)).toEqual([
      "unsupported_algorithm",
      "unsupported_algorithm",
    ]);
    expect(result.unavailableCount).toBe(2);
    expect(JSON.stringify(result)).not.toContain(fixture.encryptedEnvelope);
    expect(JSON.stringify(result)).not.toContain(fixture.encryptedPayload);
  });

  it("does not decrypt an event returned under a different chat id", async () => {
    const fixture = await createSyntheticLibsodiumEventFixture();
    await sodium.ready;
    const session = {
      version: 1,
      createdAt: "2026-01-01T00:00:00.000Z",
      rts: {
        host: "synthetic.invalid",
        authToken: "SYNTHETIC_TOKEN",
        expiresAt: null,
        userHuid: "recipient-user",
        serverId: "synthetic-server",
      },
      device: {
        udid: "synthetic-udid",
        registrationId: "synthetic-registration",
        signingKeyId: "synthetic-signing-id",
        signingAlgorithm: "ed25519",
        signingPublicKey: "SYNTHETIC_SIGNING_PUBLIC",
        signingPrivateKey: "SYNTHETIC_SIGNING_PRIVATE",
      },
      encryptionKeys: {
        rts_priv_key_body: sodium.to_base64(
          fixture.recipientPrivateKey,
          sodium.base64_variants.ORIGINAL,
        ),
      },
    } satisfies StandaloneExpressSession;
    const chat: DeviceChat = {
      connection: "rts",
      groupChatId: fixture.groupChatId,
      name: "Synthetic chat",
      chatType: "group_chat",
      encryptionKeyIds: [],
      encryptionAlgorithm: null,
      active: true,
      left: false,
      sharedHistory: true,
      lastEventSyncId: fixture.syncId,
      lastEventInsertedAt: null,
      lastIgnoreMessagesAt: null,
    };
    const key: ExpressPublicKey = {
      id: "synthetic-sender-key",
      body: sodium.to_base64(
        fixture.senderPublicKey,
        sodium.base64_variants.ORIGINAL,
      ),
      kind: "curve25519",
      algo: "xsalsa20:xchacha20_aead_ietf",
      userHuid: "verified-kdc-user",
    };

    const result = await decryptHistoryEvents(
      session,
      chat,
      {
        generatedAt: null,
        events: [
          {
            event_type: "message_new",
            group_chat_id: "different-chat",
            sync_id: fixture.syncId,
            sender_key_id: key.id,
            key: { key: fixture.encryptedEnvelope },
            payload: fixture.encryptedPayload,
          },
        ],
      },
      new Map([[key.id, key]]),
    );

    expect(result.messages).toEqual([]);
    expect(result.unavailableCount).toBe(1);
  });
});
