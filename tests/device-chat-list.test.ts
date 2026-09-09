import { describe, expect, it } from "vitest";

import { normalizeDeviceChat } from "../src/express/device-chat-list.js";

describe("device chat list normalization", () => {
  it("keeps only the bounded fields needed for discovery and history", () => {
    expect(
      normalizeDeviceChat({
        group_chat_id: "synthetic-chat",
        name: "Synthetic chat",
        chat_type: "group_chat",
        keys: ["synthetic-recipient-key"],
        // Observed corporate chat profile. New message events inside this chat
        // still use the xchacha20_aead_ietf envelope.
        algo: "xsalsa20:chacha20",
        active: true,
        left: false,
        shared_history: true,
        last_event_sync_id: "synthetic-sync",
        last_event_inserted_at: "2026-09-06T12:00:00.000Z",
        chat_settings: {
          last_ignore_messages_at: "2026-01-01T00:00:00.000Z",
          unrelated: "discarded",
        },
        member_huids: ["discarded"],
      }),
    ).toEqual({
      connection: "rts",
      groupChatId: "synthetic-chat",
      name: "Synthetic chat",
      chatType: "group_chat",
      encryptionKeyIds: ["synthetic-recipient-key"],
      encryptionAlgorithm: "xsalsa20:chacha20",
      active: true,
      left: false,
      sharedHistory: true,
      lastEventSyncId: "synthetic-sync",
      lastEventInsertedAt: "2026-09-06T12:00:00.000Z",
      lastIgnoreMessagesAt: "2026-01-01T00:00:00.000Z",
    });
  });
});
