import { describe, expect, it, vi } from "vitest";
import { createHash, randomUUID } from "node:crypto";

import { withCtsRefreshLock } from "../src/auth/cts-refresh-lock.js";
import type { StandaloneExpressSession } from "../src/auth/standalone-qr-client.js";
import type { DeviceChatList } from "../src/express/device-chat-list.js";
import { MessageDeliveryError } from "../src/express/message-send-client.js";
import { createExpressMcpServer } from "../src/mcp/server.js";

type ToolHandler = (
  args: Record<string, unknown>,
  context: Record<string, unknown>,
) => Promise<Record<string, unknown>>;

function toolHandler(
  server: ReturnType<typeof createExpressMcpServer>,
  name: string,
): ToolHandler {
  const registered = server as unknown as {
    _registeredTools: Record<string, { handler: ToolHandler }>;
  };
  return registered._registeredTools[name]!.handler;
}

function toolContext(
  inputResponses?: Record<string, unknown>,
  signal: AbortSignal = new AbortController().signal,
  requestState?: Record<string, unknown>,
) {
  return {
    mcpReq: {
      id: "synthetic-request",
      method: "tools/call",
      signal,
      inputResponses,
      requestState: () => requestState,
    },
  };
}

function sendConfirmationState(input: {
  chatId: string;
  text: string;
  idempotencyKey: string;
  scope: "corporate" | "personal";
}, session: StandaloneExpressSession = SESSION) {
  const connection = input.scope === "corporate" ? session.cts : session.rts;
  if (!connection) {
    throw new Error("synthetic scope is not connected");
  }
  const principalHash = createHash("sha256")
    .update(JSON.stringify({
      scope: input.scope,
      host: connection.host,
      serverId: connection.serverId,
      userHuid: connection.userHuid,
      registrationId: session.device.registrationId,
    }))
    .digest("hex");
  return {
    operation: "message.send",
    scope: input.scope,
    principalHash,
    chatId: input.chatId,
    textHash: createHash("sha256").update(input.text).digest("hex"),
    idempotencyKey: input.idempotencyKey,
  };
}

function mockSendJournal(
  beginResult:
    | "new"
    | "acknowledged"
    | "uncertain"
    | "retired"
    | "mismatch" = "new",
) {
  return {
    begin: vi.fn().mockResolvedValue(beginResult),
    acknowledge: vi.fn().mockResolvedValue(undefined),
    markUnknown: vi.fn().mockResolvedValue(undefined),
    clearKnownFailure: vi.fn().mockResolvedValue(undefined),
  };
}

const SESSION = {
  version: 1,
  createdAt: "2026-01-01T00:00:00.000Z",
  rts: {
    host: "synthetic.invalid",
    authToken: "SYNTHETIC_TOKEN",
    expiresAt: null,
    userHuid: "synthetic-user",
    serverId: "synthetic-server",
  },
  device: {
    udid: "synthetic-udid",
    registrationId: "synthetic-registration",
    signingKeyId: "synthetic-sign-key",
    signingAlgorithm: "ed25519",
    signingPublicKey: "SYNTHETIC_PUBLIC",
    signingPrivateKey: "SYNTHETIC_PRIVATE",
  },
  requestSigning: {
    publicKeyId: "synthetic-request-key",
    privateKeyId: "synthetic-request-private",
    algorithm: "ed25519",
    publicKey: "SYNTHETIC_PUBLIC",
    privateKey: "SYNTHETIC_PRIVATE",
    uploaded: true,
    uploadedConnections: ["rts"],
  },
  encryptionKeys: {},
} satisfies StandaloneExpressSession;

const CHAT_LIST: DeviceChatList = {
  generatedAt: "2026-09-06T12:00:00.000Z",
  chats: [
    {
      connection: "rts",
      groupChatId: "visible-chat",
      name: "Visible chat",
      chatType: "group_chat",
      encryptionKeyIds: ["synthetic-recipient-key"],
      encryptionAlgorithm: "xsalsa20:xchacha20_aead_ietf",
      active: true,
      left: false,
      sharedHistory: true,
      lastEventSyncId: "last-sync",
      lastEventInsertedAt: "2026-09-06T11:00:00.000Z",
      lastIgnoreMessagesAt: null,
    },
  ],
};

function corporateSession(
  overrides: Partial<NonNullable<StandaloneExpressSession["cts"]>> = {},
): StandaloneExpressSession {
  return {
    ...SESSION,
    cts: {
      host: "corporate.synthetic.invalid",
      accessToken: "SYNTHETIC_OLD_CTS_TOKEN",
      refreshToken: "SYNTHETIC_OLD_REFRESH_TOKEN",
      expiresIn: 1,
      expiresAt: "2026-01-01T00:00:01.000Z",
      userHuid: "synthetic-user",
      serverId: "synthetic-corporate-server",
      active: true,
      ...overrides,
    },
  };
}

describe("eXpress MCP server", () => {
  it("constructs with injected connector dependencies", () => {
    const server = createExpressMcpServer({
      sessionStore: { load: vi.fn().mockResolvedValue(SESSION) },
      fetchChatList: vi.fn().mockResolvedValue(CHAT_LIST),
      readHistory: vi.fn(),
    });

    expect(server).toBeDefined();
  });

  it("reports the observed legacy chat profile as send-compatible", async () => {
    const server = createExpressMcpServer({
      sessionStore: { load: vi.fn().mockResolvedValue(SESSION) },
      fetchChatList: vi.fn().mockResolvedValue({
        ...CHAT_LIST,
        chats: CHAT_LIST.chats.map((chat) => ({
          ...chat,
          encryptionAlgorithm: "xsalsa20:chacha20",
        })),
      }),
      readHistory: vi.fn(),
    });

    const result = await toolHandler(server, "express_list_chats")(
      { includeLeft: false, scope: "personal" },
      toolContext(),
    );
    const structured = result.structuredContent as {
      chats: Array<{ sendCompatible: boolean }>;
    };

    expect(result.isError).not.toBe(true);
    expect(structured.chats[0]?.sendCompatible).toBe(true);
  });

  it("keeps message sending disabled without process-owner opt-in", async () => {
    const sendMessage = vi.fn();
    const server = createExpressMcpServer({
      allowSend: false,
      sessionStore: { load: vi.fn().mockResolvedValue(SESSION) },
      fetchChatList: vi.fn().mockResolvedValue(CHAT_LIST),
      sendMessage,
    });

    const result = await toolHandler(server, "express_send_message")(
      {
        chatId: "visible-chat",
        text: "synthetic text",
        idempotencyKey: "59dc4b2c-525d-4dc4-ab4c-1e3e70958222",
        scope: "personal",
      },
      toolContext(),
    );

    expect(result.isError).toBe(true);
    expect(sendMessage).not.toHaveBeenCalled();
  });

  it("requests trusted client confirmation before sending", async () => {
    const sendMessage = vi.fn();
    const server = createExpressMcpServer({
      allowSend: true,
      sessionStore: { load: vi.fn().mockResolvedValue(SESSION) },
      fetchChatList: vi.fn().mockResolvedValue(CHAT_LIST),
      sendMessage,
    });

    const result = await toolHandler(server, "express_send_message")(
      {
        chatId: "visible-chat",
        text: "synthetic text",
        idempotencyKey: "93416789-a0ad-4138-8796-4d13489dbeb4",
        scope: "personal",
      },
      toolContext(),
    );

    expect(result).toHaveProperty("inputRequests.confirm-send");
    expect(sendMessage).not.toHaveBeenCalled();
  });

  it("shows the immutable destination and escaped full text in confirmation", async () => {
    const longText = `${"x".repeat(260)}\nsecret\u202epart\u200b\u2060\ufeff\u2028\u2029`;
    const chatList: DeviceChatList = {
      ...CHAT_LIST,
      chats: [
        {
          ...CHAT_LIST.chats[0]!,
          name: "Trusted\u202ename",
        },
      ],
    };
    const server = createExpressMcpServer({
      allowSend: true,
      sessionStore: { load: vi.fn().mockResolvedValue(SESSION) },
      fetchChatList: vi.fn().mockResolvedValue(chatList),
      sendMessage: vi.fn(),
    });
    const result = await toolHandler(server, "express_send_message")(
      {
        chatId: "visible-chat",
        text: longText,
        idempotencyKey: "88b26230-fc05-4c55-af42-d8e103add4ee",
        scope: "personal",
      },
      toolContext(),
    );
    const confirmation = result.inputRequests as {
      "confirm-send": { params: { message: string } };
    };
    const message = confirmation["confirm-send"].params.message;

    expect(message).toContain('name: "Trusted\\\\u202ename"');
    expect(message).toContain('chatId: "visible-chat"');
    expect(message).toContain(`text: "${"x".repeat(260)}`);
    expect(message).toContain("\\nsecret\\\\u202epart");
    expect(message).not.toContain("\u202e");
    for (const invisible of ["\u200b", "\u2060", "\ufeff", "\u2028", "\u2029"]) {
      expect(message).not.toContain(invisible);
    }
  });

  it("sends only after an accepted client confirmation", async () => {
    const sendJournal = mockSendJournal();
    const sendMessage = vi.fn().mockResolvedValue({
      status: "acknowledged",
      chatId: "visible-chat",
      syncId: "24ee20fe-fdb3-420b-9360-0c563abe91b1",
      insertedAt: "2026-09-08T12:00:00.000Z",
    });
    const server = createExpressMcpServer({
      allowSend: true,
      sessionStore: { load: vi.fn().mockResolvedValue(SESSION) },
      fetchChatList: vi.fn().mockResolvedValue(CHAT_LIST),
      sendMessage,
      sendJournal,
    });

    const input = {
      chatId: "visible-chat",
      text: "synthetic text",
      idempotencyKey: "24ee20fe-fdb3-420b-9360-0c563abe91b1",
      scope: "personal" as const,
    };
    const result = await toolHandler(server, "express_send_message")(
      input,
      toolContext({
        "confirm-send": { action: "accept", content: { confirm: true } },
      }, undefined, sendConfirmationState(input)),
    );

    expect(result).toHaveProperty("structuredContent.status", "acknowledged");
    expect(sendMessage).toHaveBeenCalledOnce();
    expect(sendJournal.begin).toHaveBeenCalledOnce();
    expect(sendJournal.acknowledge).toHaveBeenCalledWith(
      input.idempotencyKey,
      expect.stringMatching(/^[0-9a-f]{64}$/),
      "2026-09-08T12:00:00.000Z",
    );
  });

  it("returns a durable acknowledgement without sending a duplicate", async () => {
    const sendJournal = mockSendJournal("acknowledged");
    const sendMessage = vi.fn();
    const server = createExpressMcpServer({
      allowSend: true,
      sessionStore: { load: vi.fn().mockResolvedValue(SESSION) },
      fetchChatList: vi.fn().mockResolvedValue(CHAT_LIST),
      sendMessage,
      sendJournal,
    });
    const input = {
      chatId: "visible-chat",
      text: "already delivered",
      idempotencyKey: "0bd31749-b10f-4349-9724-4b592f560c89",
      scope: "personal" as const,
    };

    const result = await toolHandler(server, "express_send_message")(
      input,
      toolContext(
        { "confirm-send": { action: "accept", content: { confirm: true } } },
        undefined,
        sendConfirmationState(input),
      ),
    );

    expect(result).toHaveProperty("structuredContent.status", "acknowledged");
    expect(result).toHaveProperty("structuredContent.insertedAt", null);
    expect(sendMessage).not.toHaveBeenCalled();
    expect(sendJournal.acknowledge).not.toHaveBeenCalled();
  });

  it("fails closed when an earlier durable send outcome is uncertain", async () => {
    const sendJournal = mockSendJournal("uncertain");
    const sendMessage = vi.fn();
    const server = createExpressMcpServer({
      allowSend: true,
      sessionStore: { load: vi.fn().mockResolvedValue(SESSION) },
      fetchChatList: vi.fn().mockResolvedValue(CHAT_LIST),
      sendMessage,
      sendJournal,
    });
    const input = {
      chatId: "visible-chat",
      text: "uncertain delivery",
      idempotencyKey: "3a888baa-88f7-4ec3-b5c2-ee2549f62e16",
      scope: "personal" as const,
    };

    const result = await toolHandler(server, "express_send_message")(
      input,
      toolContext(
        { "confirm-send": { action: "accept", content: { confirm: true } } },
        undefined,
        sendConfirmationState(input),
      ),
    );

    expect(result).toHaveProperty("structuredContent.status", "unknown");
    expect(sendMessage).not.toHaveBeenCalled();
  });

  it("requires a new UUID after an outcome is reconciled as not delivered", async () => {
    const sendJournal = mockSendJournal("retired");
    const sendMessage = vi.fn();
    const server = createExpressMcpServer({
      allowSend: true,
      sessionStore: { load: vi.fn().mockResolvedValue(SESSION) },
      fetchChatList: vi.fn().mockResolvedValue(CHAT_LIST),
      sendMessage,
      sendJournal,
    });
    const input = {
      chatId: "visible-chat",
      text: "must require a fresh confirmation",
      idempotencyKey: "e9972185-0141-46f4-8f05-849fd9993009",
      scope: "personal" as const,
    };

    const result = await toolHandler(server, "express_send_message")(
      input,
      toolContext(
        { "confirm-send": { action: "accept", content: { confirm: true } } },
        undefined,
        sendConfirmationState(input),
      ),
    );

    expect(result.isError).toBe(true);
    expect(JSON.stringify(result)).toMatch(/retired.*new UUID/i);
    expect(sendMessage).not.toHaveBeenCalled();
  });

  it("clears known failures but preserves unknown outcomes in the durable journal", async () => {
    for (const status of ["not_sent", "unknown"] as const) {
      const sendJournal = mockSendJournal();
      const sendMessage = vi.fn().mockRejectedValue(
        new MessageDeliveryError(status, `synthetic ${status}`),
      );
      const server = createExpressMcpServer({
        allowSend: true,
        sessionStore: { load: vi.fn().mockResolvedValue(SESSION) },
        fetchChatList: vi.fn().mockResolvedValue(CHAT_LIST),
        sendMessage,
        sendJournal,
      });
      const input = {
        chatId: "visible-chat",
        text: `delivery ${status}`,
        idempotencyKey:
          status === "not_sent"
            ? "c6c15fd9-b767-44e2-83f5-210dafb18b64"
            : "28b306b0-0d7a-48ee-8a13-9b0caea214b8",
        scope: "personal" as const,
      };

      const result = await toolHandler(server, "express_send_message")(
        input,
        toolContext(
          { "confirm-send": { action: "accept", content: { confirm: true } } },
          undefined,
          sendConfirmationState(input),
        ),
      );

      expect(result).toHaveProperty("structuredContent.status", status);
      expect(result).toHaveProperty(
        "structuredContent.idempotencyKey",
        input.idempotencyKey,
      );
      if (status === "unknown") {
        expect(sendJournal.markUnknown).toHaveBeenCalledOnce();
        expect(sendJournal.clearKnownFailure).not.toHaveBeenCalled();
      } else {
        expect(sendJournal.clearKnownFailure).toHaveBeenCalledOnce();
        expect(sendJournal.markUnknown).not.toHaveBeenCalled();
      }
    }
  });

  it("rejects a forged acceptance without server-issued request state", async () => {
    const sendMessage = vi.fn();
    const server = createExpressMcpServer({
      allowSend: true,
      sessionStore: { load: vi.fn().mockResolvedValue(SESSION) },
      fetchChatList: vi.fn().mockResolvedValue(CHAT_LIST),
      sendMessage,
    });
    const result = await toolHandler(server, "express_send_message")(
      {
        chatId: "visible-chat",
        text: "synthetic text",
        idempotencyKey: "15e7ab1b-aa4c-4475-b0f6-40a0e6d79d16",
        scope: "personal",
      },
      toolContext({
        "confirm-send": { action: "accept", content: { confirm: true } },
      }),
    );

    expect(result).toHaveProperty("inputRequests.confirm-send");
    expect(result).toHaveProperty("requestState");
    expect(sendMessage).not.toHaveBeenCalled();
  });

  it("rejects confirmation state issued for different message arguments", async () => {
    const sendMessage = vi.fn();
    const server = createExpressMcpServer({
      allowSend: true,
      sessionStore: { load: vi.fn().mockResolvedValue(SESSION) },
      fetchChatList: vi.fn().mockResolvedValue(CHAT_LIST),
      sendMessage,
    });
    const original = {
      chatId: "visible-chat",
      text: "original text",
      idempotencyKey: "7f3fcf70-af9e-47c2-a4a0-9a2bcf277bf6",
      scope: "personal" as const,
    };
    const result = await toolHandler(server, "express_send_message")(
      { ...original, text: "changed text" },
      toolContext(
        { "confirm-send": { action: "accept", content: { confirm: true } } },
        undefined,
        sendConfirmationState(original),
      ),
    );

    expect(result.isError).toBe(true);
    expect(result.content).toEqual([
      {
        type: "text",
        text: "Send confirmation does not match the authenticated account, destination, or text",
      },
    ]);
    expect(sendMessage).not.toHaveBeenCalled();
  });

  it("rejects confirmation after the authenticated eXpress principal changes", async () => {
    const changedSession: StandaloneExpressSession = {
      ...SESSION,
      rts: {
        ...SESSION.rts,
        host: "other.synthetic.invalid",
        serverId: "other-server",
        userHuid: "other-user",
      },
      device: {
        ...SESSION.device,
        registrationId: "other-registration",
      },
    };
    const sendMessage = vi.fn();
    const server = createExpressMcpServer({
      allowSend: true,
      sessionStore: { load: vi.fn().mockResolvedValue(changedSession) },
      fetchChatList: vi.fn().mockResolvedValue(CHAT_LIST),
      sendMessage,
      sendJournal: mockSendJournal(),
    });
    const input = {
      chatId: "visible-chat",
      text: "must stay on the original account",
      idempotencyKey: "b33b7614-711c-499e-838f-3e22c12af8ed",
      scope: "personal" as const,
    };

    const result = await toolHandler(server, "express_send_message")(
      input,
      toolContext(
        { "confirm-send": { action: "accept", content: { confirm: true } } },
        undefined,
        sendConfirmationState(input, SESSION),
      ),
    );

    expect(result.isError).toBe(true);
    expect(result.content).toEqual([{
      type: "text",
      text: "Send confirmation does not match the authenticated account, destination, or text",
    }]);
    expect(sendMessage).not.toHaveBeenCalled();
  });

  it("serializes CTS refresh across MCP server instances", async () => {
    let stored = corporateSession();
    const save = vi.fn(async (session: StandaloneExpressSession) => {
      stored = session;
    });
    const lockId = `synthetic-mcp-${randomUUID()}`;
    const sessionStore = {
      load: vi.fn(async () => stored),
      save,
      withExclusiveAccess: <T>(
        signal: AbortSignal,
        operation: () => Promise<T>,
      ) => withCtsRefreshLock(lockId, signal, operation),
    };
    const refreshCts = vi.fn(async (session: StandaloneExpressSession) => {
      if (session.cts?.accessToken !== "SYNTHETIC_OLD_CTS_TOKEN") {
        return session;
      }
      await new Promise((resolve) => setTimeout(resolve, 50));
      return corporateSession({
        accessToken: "SYNTHETIC_NEW_CTS_TOKEN",
        refreshToken: "SYNTHETIC_NEW_REFRESH_TOKEN",
        expiresIn: 3600,
        expiresAt: "2026-01-01T01:00:00.000Z",
      });
    });
    const dependencies = {
      sessionStore,
      refreshCts,
      fetchChatList: vi.fn().mockResolvedValue({
        ...CHAT_LIST,
        chats: CHAT_LIST.chats.map((chat) => ({ ...chat, connection: "cts" as const })),
      }),
    };
    const firstServer = createExpressMcpServer(dependencies);
    const secondServer = createExpressMcpServer(dependencies);

    const [first, second] = await Promise.all([
      toolHandler(firstServer, "express_list_chats")(
        { includeLeft: false, scope: "corporate" },
        toolContext(),
      ),
      toolHandler(secondServer, "express_list_chats")(
        { includeLeft: false, scope: "corporate" },
        toolContext(),
      ),
    ]);

    expect(first.isError).not.toBe(true);
    expect(second.isError).not.toBe(true);
    expect(refreshCts).toHaveBeenCalledTimes(2);
    expect(save).toHaveBeenCalledOnce();
    expect(stored.cts?.accessToken).toBe("SYNTHETIC_NEW_CTS_TOKEN");
  });

  it("aborts the underlying CTS refresh when the MCP request is cancelled", async () => {
    const controller = new AbortController();
    const save = vi.fn();
    const refreshCts = vi.fn(
      async (
        _session: StandaloneExpressSession,
        options: { signal?: AbortSignal },
      ): Promise<StandaloneExpressSession> =>
        new Promise((_resolve, reject) => {
          options.signal?.addEventListener(
            "abort",
            () => reject(new Error("CTS refresh cancelled")),
            { once: true },
          );
        }),
    );
    const server = createExpressMcpServer({
      sessionStore: {
        load: vi.fn().mockResolvedValue(corporateSession()),
        save,
        withExclusiveAccess: async (_signal, operation) => operation(),
      },
      refreshCts,
      fetchChatList: vi.fn(),
    });
    const pending = toolHandler(server, "express_list_chats")(
      { includeLeft: false, scope: "corporate" },
      toolContext(undefined, controller.signal),
    );

    await vi.waitFor(() => expect(refreshCts).toHaveBeenCalledOnce());
    controller.abort();
    const result = await pending;

    expect(result.isError).toBe(true);
    expect(save).not.toHaveBeenCalled();
  });

  it("merges refreshed CTS fields into the latest session snapshot", async () => {
    const initial = corporateSession();
    const latest = {
      ...initial,
      requestSigning: {
        ...initial.requestSigning!,
        uploadedConnections: ["rts", "cts"] as Array<"rts" | "cts">,
      },
      encryptionKeys: { newlyTransferred: "SYNTHETIC_KEY" },
    };
    const load = vi
      .fn()
      .mockResolvedValueOnce(initial)
      .mockResolvedValueOnce(latest);
    const save = vi.fn();
    const refreshed = corporateSession({
      accessToken: "SYNTHETIC_NEW_CTS_TOKEN",
      refreshToken: "SYNTHETIC_NEW_REFRESH_TOKEN",
    });
    const server = createExpressMcpServer({
      sessionStore: {
        load,
        save,
        withExclusiveAccess: async (_signal, operation) => operation(),
      },
      refreshCts: vi.fn().mockResolvedValue(refreshed),
      fetchChatList: vi.fn().mockResolvedValue(CHAT_LIST),
    });

    const result = await toolHandler(server, "express_list_chats")(
      { includeLeft: false, scope: "corporate" },
      toolContext(),
    );

    expect(result.isError).not.toBe(true);
    expect(save).toHaveBeenCalledWith({
      ...latest,
      cts: refreshed.cts,
    });
  });

  it("keeps concurrent corporate chat histories isolated by chat id", async () => {
    const corporateSession = {
      ...SESSION,
      cts: {
        host: "corporate.synthetic.invalid",
        accessToken: "SYNTHETIC_CTS_TOKEN",
        refreshToken: null,
        expiresIn: null,
        expiresAt: null,
        userHuid: "synthetic-user",
        serverId: "synthetic-corporate-server",
        active: true,
      },
    } satisfies StandaloneExpressSession;
    const chats: DeviceChatList = {
      generatedAt: "2026-09-08T14:30:00.000Z",
      chats: ["test-1", "test-2"].map((chatId, index) => ({
        ...CHAT_LIST.chats[0]!,
        connection: "cts" as const,
        groupChatId: chatId,
        name: `test ${index + 1}`,
        lastEventSyncId: `sync-${index + 1}`,
      })),
    };
    const fetchChatList = vi.fn().mockResolvedValue(chats);
    const readHistory = vi.fn(async (_session, chat) => ({
      chatId: chat.groupChatId,
      chatName: chat.name,
      messages: [
        {
          syncId: `message-${chat.groupChatId}`,
          eventType: "message_new",
          insertedAt: "2026-09-08T14:30:00.000Z",
          messageId: `message-${chat.groupChatId}`,
          senderId: "synthetic-user",
          kind: "text",
          body: `history for ${chat.name}`,
          replyToMessageId: null,
          attachmentFileId: null,
          senderClaimMismatch: false,
          status: "decrypted" as const,
        },
      ],
      unavailableCount: 0,
      nextBeforeSyncId: null,
      generatedAt: "2026-09-08T14:30:00.000Z",
      anchorExcluded: false,
      anchorUnavailable: false,
    }));
    const server = createExpressMcpServer({
      sessionStore: { load: vi.fn().mockResolvedValue(corporateSession) },
      refreshCts: vi.fn().mockResolvedValue(corporateSession),
      fetchChatList,
      readHistory,
    });
    const getHistory = toolHandler(server, "express_get_history");

    const [first, second] = await Promise.all([
      getHistory(
        { chatId: "test-1", limit: 20, scope: "corporate" },
        toolContext(),
      ),
      getHistory(
        { chatId: "test-2", limit: 20, scope: "corporate" },
        toolContext(),
      ),
    ]);

    expect(first).toHaveProperty("structuredContent.chatId", "test-1");
    expect(first).toHaveProperty(
      "structuredContent.messages.0.body",
      "history for test 1",
    );
    expect(second).toHaveProperty("structuredContent.chatId", "test-2");
    expect(second).toHaveProperty(
      "structuredContent.messages.0.body",
      "history for test 2",
    );
    expect(fetchChatList).toHaveBeenCalledTimes(2);
    expect(fetchChatList).toHaveBeenNthCalledWith(
      1,
      corporateSession,
      expect.objectContaining({ connection: "cts" }),
    );
    expect(fetchChatList).toHaveBeenNthCalledWith(
      2,
      corporateSession,
      expect.objectContaining({ connection: "cts" }),
    );
    expect(readHistory).toHaveBeenCalledTimes(2);
  });

  it("does not send after the MCP request is cancelled", async () => {
    const controller = new AbortController();
    const sendMessage = vi.fn();
    const fetchChatList = vi.fn(
      async (
        _session: StandaloneExpressSession,
        options: { signal?: AbortSignal },
      ): Promise<DeviceChatList> =>
        new Promise((_resolve, reject) => {
          options.signal?.addEventListener(
            "abort",
            () => reject(new Error("chat discovery cancelled")),
            { once: true },
          );
        }),
    );
    const server = createExpressMcpServer({
      allowSend: true,
      sessionStore: { load: vi.fn().mockResolvedValue(SESSION) },
      fetchChatList,
      sendMessage,
    });
    const pending = toolHandler(server, "express_send_message")(
      {
        chatId: "visible-chat",
        text: "must not be sent",
        idempotencyKey: "5d78bd7a-474e-4354-9d58-0c18db8ee76b",
        scope: "personal",
      },
      toolContext(
        { "confirm-send": { action: "accept", content: { confirm: true } } },
        controller.signal,
        sendConfirmationState({
          chatId: "visible-chat",
          text: "must not be sent",
          idempotencyKey: "5d78bd7a-474e-4354-9d58-0c18db8ee76b",
          scope: "personal",
        }),
      ),
    );

    await vi.waitFor(() => expect(fetchChatList).toHaveBeenCalledOnce());
    controller.abort();
    const result = await pending;

    expect(result.isError).toBe(true);
    expect(result.content).toEqual([
      { type: "text", text: "chat discovery cancelled" },
    ]);
    expect(sendMessage).not.toHaveBeenCalled();
  });
});
