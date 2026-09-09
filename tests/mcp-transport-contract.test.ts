import {
  InMemoryTransport,
  type JSONRPCMessage,
} from "@modelcontextprotocol/server";
import { describe, expect, it, vi } from "vitest";

import type { StandaloneExpressSession } from "../src/auth/standalone-qr-client.js";
import type { DeviceChatList } from "../src/express/device-chat-list.js";
import { createExpressMcpServer } from "../src/mcp/server.js";

type JsonRecord = Record<string, unknown>;

const SESSION = {
  version: 1,
  createdAt: "2026-01-01T00:00:00.000Z",
  rts: {
    host: "synthetic.invalid",
    authToken: "SYNTHETIC_SECRET_TOKEN",
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
    signingPrivateKey: "SYNTHETIC_SECRET_PRIVATE_KEY",
  },
  encryptionKeys: {},
} satisfies StandaloneExpressSession;

const CHAT_LIST: DeviceChatList = {
  generatedAt: "2026-09-08T12:00:00.000Z",
  chats: [{
    connection: "rts",
    groupChatId: "transport-chat",
    name: "Transport test chat",
    chatType: "group_chat",
    encryptionKeyIds: ["synthetic-key"],
    encryptionAlgorithm: "xsalsa20:xchacha20_aead_ietf",
    active: true,
    left: false,
    sharedHistory: true,
    lastEventSyncId: null,
    lastEventInsertedAt: null,
    lastIgnoreMessagesAt: null,
  }],
};

function asRecord(value: unknown): JsonRecord {
  expect(value).not.toBeNull();
  expect(typeof value).toBe("object");
  expect(Array.isArray(value)).toBe(false);
  return value as JsonRecord;
}

describe("eXpress MCP public transport contract", () => {
  it("negotiates, lists tools, validates schemas, and serves status", async () => {
    const load = vi.fn().mockResolvedValue(SESSION);
    const fetchChatList = vi.fn().mockResolvedValue(CHAT_LIST);
    const readHistory = vi.fn();
    const sendMessage = vi.fn();
    const refreshCts = vi.fn();
    const server = createExpressMcpServer({
      sessionStore: { load },
      fetchChatList,
      readHistory,
      sendMessage,
      refreshCts,
      allowSend: true,
      sendJournal: {
        begin: vi.fn().mockResolvedValue("new" as const),
        acknowledge: vi.fn().mockResolvedValue(undefined),
        markUnknown: vi.fn().mockResolvedValue(undefined),
        clearKnownFailure: vi.fn().mockResolvedValue(undefined),
      },
    });
    const [clientTransport, serverTransport] =
      InMemoryTransport.createLinkedPair();
    let nextId = 1;
    const responses = new Map<
      number,
      { resolve: (message: JsonRecord) => void; reject: (error: Error) => void }
    >();
    clientTransport.onmessage = async (message) => {
      const record = message as unknown as JsonRecord;
      const id = record.id;
      if (record.method === "elicitation/create" && typeof id === "number") {
        await clientTransport.send({
          jsonrpc: "2.0",
          id,
          result: { action: "accept", content: { confirm: true } },
        } as JSONRPCMessage);
        return;
      }
      if (typeof id === "number") {
        responses.get(id)?.resolve(record);
        responses.delete(id);
      }
    };
    clientTransport.onerror = (error) => {
      for (const pending of responses.values()) {
        pending.reject(error);
      }
      responses.clear();
    };

    const request = async (
      method: string,
      params: JsonRecord,
    ): Promise<JsonRecord> => {
      const id = nextId++;
      let timeout: ReturnType<typeof setTimeout> | undefined;
      const response = new Promise<JsonRecord>((resolve, reject) => {
        responses.set(id, { resolve, reject });
        timeout = setTimeout(() => {
          responses.delete(id);
          reject(new Error(`Timed out waiting for ${method}`));
        }, 2_000);
      });
      try {
        await clientTransport.send({
          jsonrpc: "2.0",
          id,
          method,
          params,
        } as JSONRPCMessage);
        return await response;
      } finally {
        if (timeout) {
          clearTimeout(timeout);
        }
      }
    };

    try {
      await server.connect(serverTransport);
      await clientTransport.start();

      const initialized = await request("initialize", {
        protocolVersion: "2025-06-18",
        capabilities: { elicitation: {} },
        clientInfo: { name: "transport-contract-test", version: "1.0.0" },
      });
      expect(initialized.error).toBeUndefined();
      expect(initialized.result).toMatchObject({
        protocolVersion: "2025-06-18",
        serverInfo: {
          name: "eXpress MCP connector",
          version: "0.1.0",
        },
        capabilities: { tools: {} },
      });
      await clientTransport.send({
        jsonrpc: "2.0",
        method: "notifications/initialized",
      } as JSONRPCMessage);

      const listed = await request("tools/list", {});
      expect(listed.error).toBeUndefined();
      const tools = asRecord(listed.result).tools;
      expect(Array.isArray(tools)).toBe(true);
      expect(
        (tools as JsonRecord[]).map((tool) => tool.name),
      ).toEqual([
        "express_status",
        "express_list_chats",
        "express_get_history",
        "express_send_message",
      ]);
      const historyTool = (tools as JsonRecord[]).find(
        (tool) => tool.name === "express_get_history",
      );
      expect(asRecord(historyTool?.inputSchema).required).toContain("chatId");

      const malformed = await request("tools/call", {
        name: "express_get_history",
        arguments: { chatId: "", limit: 0, scope: "corporate" },
      });
      expect(malformed.error).toBeUndefined();
      expect(asRecord(malformed.result).isError).toBe(true);
      expect(load).not.toHaveBeenCalled();
      expect(fetchChatList).not.toHaveBeenCalled();
      expect(readHistory).not.toHaveBeenCalled();

      const status = await request("tools/call", {
        name: "express_status",
        arguments: {},
      });
      expect(status.error).toBeUndefined();
      expect(asRecord(status.result).structuredContent).toMatchObject({
        connected: true,
        rtsReady: true,
        ctsReady: false,
      });
      expect(JSON.stringify(status)).not.toContain("SYNTHETIC_SECRET_TOKEN");
      expect(JSON.stringify(status)).not.toContain(
        "SYNTHETIC_SECRET_PRIVATE_KEY",
      );
      expect(load).toHaveBeenCalledOnce();
      expect(fetchChatList).not.toHaveBeenCalled();
      expect(readHistory).not.toHaveBeenCalled();
      expect(sendMessage).not.toHaveBeenCalled();
      expect(refreshCts).not.toHaveBeenCalled();

      sendMessage.mockResolvedValue({
        status: "acknowledged",
        chatId: "transport-chat",
        syncId: "18881261-b5a2-4680-aa09-21319b218ed8",
        insertedAt: "2026-09-08T12:00:00.000Z",
      });
      const sent = await request("tools/call", {
        name: "express_send_message",
        arguments: {
          chatId: "transport-chat",
          text: "confirmed through public transport",
          idempotencyKey: "18881261-b5a2-4680-aa09-21319b218ed8",
          scope: "personal",
        },
      });
      expect(sent.error).toBeUndefined();
      expect(asRecord(sent.result).structuredContent).toMatchObject({
        status: "acknowledged",
        chatId: "transport-chat",
      });
      expect(sendMessage).toHaveBeenCalledOnce();
    } finally {
      await Promise.allSettled([server.close(), clientTransport.close()]);
    }
  });
});
