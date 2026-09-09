import {
  acceptedContent,
  createRequestStateCodec,
  inputRequired,
  McpServer,
  type RequestStateCodec,
} from "@modelcontextprotocol/server";
import { serveStdio } from "@modelcontextprotocol/server/stdio";
import { createHash, randomBytes } from "node:crypto";
import { pathToFileURL } from "node:url";
import { z } from "zod";

import { APPLICATION_NAME } from "../application-identity.js";
import { NativeCredentialSessionStore } from "../auth/native-credential-session-store.js";
import { ensureFreshCtsSession } from "../auth/cts-token-refresh.js";
import type { StandaloneExpressSession } from "../auth/standalone-qr-client.js";
import { fetchDeviceChatList, type DeviceChat } from "../express/device-chat-list.js";
import { readDecryptedHistory } from "../express/decrypted-history.js";
import {
  MessageDeliveryError,
  sendEncryptedTextMessage,
  type SendMessageResult,
} from "../express/message-send-client.js";
import {
  EXPRESS_WIRE_PROFILE,
  isSupportedSendChatProfile,
} from "../express/protocol-capabilities.js";
import { ConnectorPolicyGuard } from "../policy/connector-policy-guard.js";
import {
  PersistentSendJournal,
  type BeginSendResult,
} from "./persistent-send-journal.js";
import { withConnectorLifecycleLock } from "./connector-lifecycle-lock.js";

type JsonObject = Record<string, unknown>;

interface SendJournal {
  begin(idempotencyKey: string, fingerprint: string): Promise<BeginSendResult>;
  acknowledge(
    idempotencyKey: string,
    fingerprint: string,
    insertedAt?: string,
  ): Promise<void>;
  markUnknown(idempotencyKey: string, fingerprint: string): Promise<void>;
  clearKnownFailure(idempotencyKey: string, fingerprint: string): Promise<void>;
}

export interface ExpressMcpDependencies {
  sessionStore?: Pick<NativeCredentialSessionStore, "load"> &
    Partial<Pick<NativeCredentialSessionStore, "save" | "withExclusiveAccess">>;
  policy?: ConnectorPolicyGuard;
  fetchChatList?: typeof fetchDeviceChatList;
  readHistory?: typeof readDecryptedHistory;
  sendMessage?: typeof sendEncryptedTextMessage;
  refreshCts?: typeof ensureFreshCtsSession;
  requestStateCodec?: RequestStateCodec<SendConfirmationState>;
  sendJournal?: SendJournal;
  /** Explicit process-owner opt-in for tools that write to eXpress. */
  allowSend?: boolean;
}

interface SendConfirmationState {
  operation: "message.send";
  scope: "corporate" | "personal";
  principalHash: string;
  chatId: string;
  textHash: string;
  idempotencyKey: string;
}

const MCP_OPERATION_TIMEOUT_MS = 55_000;

function operationSignal(requestSignal: AbortSignal): AbortSignal {
  return AbortSignal.any([
    requestSignal,
    AbortSignal.timeout(MCP_OPERATION_TIMEOUT_MS),
  ]);
}

async function waitForOperation<T>(
  promise: Promise<T>,
  signal: AbortSignal,
): Promise<T> {
  if (signal.aborted) {
    throw new Error("MCP operation was cancelled");
  }
  let abort!: () => void;
  const cancelled = new Promise<never>((_resolve, reject) => {
    abort = () => reject(new Error("MCP operation was cancelled"));
    signal.addEventListener("abort", abort, { once: true });
  });
  try {
    return await Promise.race([promise, cancelled]);
  } finally {
    signal.removeEventListener("abort", abort);
  }
}

function jsonResult(value: JsonObject) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(value) }],
    structuredContent: value,
  };
}

function toolError(error: unknown) {
  const message = error instanceof Error ? error.message : "Unknown connector error";
  return {
    isError: true as const,
    content: [{ type: "text" as const, text: message }],
  };
}

function deliveryErrorResult(
  error: MessageDeliveryError,
  idempotencyKey: string,
) {
  const value = {
    status: error.status,
    message: error.message,
    idempotencyKey,
  };
  return {
    isError: true as const,
    content: [{ type: "text" as const, text: JSON.stringify(value) }],
    structuredContent: value,
  };
}

function publicChat(chat: DeviceChat): JsonObject {
  return {
    scope: chat.connection === "cts" ? "corporate" : "personal",
    chatId: chat.groupChatId,
    name: chat.name,
    chatType: chat.chatType,
    active: chat.active,
    left: chat.left,
    sharedHistory: chat.sharedHistory,
    lastEventAt: chat.lastEventInsertedAt,
    sendCompatible:
      chat.active &&
      !chat.left &&
      isSupportedSendChatProfile(chat.encryptionAlgorithm),
  };
}

function confirmationLiteral(value: string): string {
  const invisiblesEscaped = value.replace(
    /[\p{Default_Ignorable_Code_Point}\u007f-\u009f\u2028\u2029]/gu,
    (character) =>
      `\\u${character.codePointAt(0)!.toString(16).padStart(4, "0")}`,
  );
  return JSON.stringify(invisiblesEscaped);
}

function sessionPrincipalHash(
  session: StandaloneExpressSession,
  scope: "corporate" | "personal",
): string {
  const connection = scope === "corporate" ? session.cts : session.rts;
  if (!connection) {
    throw new Error("The requested eXpress account scope is not connected");
  }
  return createHash("sha256")
    .update(JSON.stringify({
      scope,
      host: connection.host,
      serverId: connection.serverId,
      userHuid: connection.userHuid,
      registrationId: session.device.registrationId,
    }))
    .digest("hex");
}

export function createExpressMcpServer(
  dependencies: ExpressMcpDependencies = {},
): McpServer {
  const sessionStore = dependencies.sessionStore ?? new NativeCredentialSessionStore();
  const policy: ConnectorPolicyGuard =
    dependencies.policy ?? new ConnectorPolicyGuard();
  const fetchChats = dependencies.fetchChatList ?? fetchDeviceChatList;
  const readHistory = dependencies.readHistory ?? readDecryptedHistory;
  const sendMessage = dependencies.sendMessage ?? sendEncryptedTextMessage;
  const refreshCts = dependencies.refreshCts ?? ensureFreshCtsSession;
  const sendJournal = dependencies.sendJournal ?? new PersistentSendJournal();
  const allowSend =
    dependencies.allowSend ?? process.env.EXPRESS_ENABLE_SEND === "1";
  const requestStateCodec =
    dependencies.requestStateCodec ??
    createRequestStateCodec<SendConfirmationState>({
      key: randomBytes(32),
      ttlSeconds: 5 * 60,
      bind: (ctx) =>
        `${ctx.mcpReq.method}\0${ctx.sessionId ?? "stdio"}`,
    });
  const sendAttempts = new Map<
    string,
    { fingerprint: string; promise: Promise<SendMessageResult> }
  >();
  const server = new McpServer(
    { name: APPLICATION_NAME, version: "0.1.0" },
    {
      capabilities: { tools: {} },
      requestState: { verify: requestStateCodec.verify },
    },
  );
  const annotations = {
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: true,
  };
  const loadScopedSession = async (
    scope: "corporate" | "personal",
    signal: AbortSignal,
  ): Promise<StandaloneExpressSession> => {
    if (scope === "personal") {
      return waitForOperation(sessionStore.load(), signal);
    }
    const refreshOperation = async (): Promise<StandaloneExpressSession> => {
        const session = await sessionStore.load();
        const refreshed = await refreshCts(session, {
          signal: AbortSignal.any([signal, AbortSignal.timeout(30_000)]),
        });
        if (refreshed === session) {
          return session;
        }
        if (!sessionStore.save) {
          throw new Error("Refreshed corporate session cannot be persisted");
        }
        // Preserve signing/encryption updates written while the network
        // request was in flight. A changed session/token wins over this
        // refresh instead of being overwritten by a stale snapshot.
        const latest = await sessionStore.load();
        if (
          latest.device.registrationId !== session.device.registrationId ||
          latest.cts?.accessToken !== session.cts?.accessToken ||
          latest.cts?.refreshToken !== session.cts?.refreshToken
        ) {
          return latest;
        }
        const merged = { ...latest, cts: refreshed.cts };
        await sessionStore.save(merged);
        return merged;
    };
    const pending = sessionStore.withExclusiveAccess
      ? sessionStore.withExclusiveAccess(signal, refreshOperation)
      : refreshOperation();
    return waitForOperation(pending, signal);
  };

  server.registerTool(
    "express_status",
    {
      title: "eXpress connection status",
      description:
        "Check whether the standalone eXpress user session is available without exposing credentials.",
      inputSchema: z.object({}),
      annotations,
    },
    async () => {
      try {
        const session = await sessionStore.load();
        const uploadedConnections = session.requestSigning?.uploadedConnections;
        return jsonResult({
          connected: true,
          wireProfile: EXPRESS_WIRE_PROFILE,
          sessionCreatedAt: session.createdAt,
          rtsReady: session.rts.authToken.length > 0,
          requestSigningReady: session.requestSigning?.uploaded === true,
          corporateSigningReady:
            session.requestSigning?.uploaded === true &&
            uploadedConnections?.includes("cts") === true,
          personalSigningReady:
            session.requestSigning?.uploaded === true &&
            uploadedConnections?.includes("rts") === true,
          ctsReady: session.cts?.active === true,
          ctsPending: session.ctsPending !== undefined,
          ctsEmailPending: session.ctsEmailPending !== undefined,
          ctsExpiresAt: session.cts?.expiresAt ?? null,
        });
      } catch (error) {
        return toolError(error);
      }
    },
  );

  server.registerTool(
    "express_list_chats",
    {
      title: "List my eXpress chats",
      description:
        "List chats and direct conversations visible to the authenticated eXpress user.",
      inputSchema: z.object({
        query: z.string().trim().max(200).optional(),
        includeLeft: z.boolean().default(false),
        scope: z.enum(["corporate", "personal"]).default("corporate"),
      }),
      annotations,
    },
    async ({ query, includeLeft, scope }, ctx) => {
      try {
        const signal = operationSignal(ctx.mcpReq.signal);
        policy.assertAllowed("chats.discover");
        const session = await loadScopedSession(scope, signal);
        const chatList = await fetchChats(session, {
          timeoutMs: 20_000,
          connection: scope === "corporate" ? "cts" : "rts",
          signal,
        });
        const needle = query?.toLocaleLowerCase();
        const chats = chatList.chats
          .filter((chat) => includeLeft || !chat.left)
          .filter(
            (chat) =>
              !needle || chat.name?.toLocaleLowerCase().includes(needle) === true,
          )
          .sort((left, right) =>
            (right.lastEventInsertedAt ?? "").localeCompare(
              left.lastEventInsertedAt ?? "",
            ),
          )
          .map(publicChat);
        return jsonResult({ chats, count: chats.length, generatedAt: chatList.generatedAt });
      } catch (error) {
        return toolError(error);
      }
    },
  );

  server.registerTool(
    "express_get_history",
    {
      title: "Read eXpress chat history",
      description:
        "Read and locally decrypt one backward page from a chat visible to the authenticated user. Use nextBeforeSyncId to request older pages.",
      inputSchema: z.object({
        chatId: z.string().trim().min(1).max(300),
        limit: z.number().int().min(1).max(100).default(50),
        beforeSyncId: z.string().trim().min(1).max(300).optional(),
        scope: z.enum(["corporate", "personal"]).default("corporate"),
      }),
      annotations,
    },
    async ({ chatId, limit, beforeSyncId, scope }, ctx) => {
      try {
        const signal = operationSignal(ctx.mcpReq.signal);
        policy.assertAllowed("chats.discover");
        policy.assertAllowed("history.read");
        policy.assertAllowed("keys.read");
        const session = await loadScopedSession(scope, signal);
        const chatList = await fetchChats(session, {
          timeoutMs: 20_000,
          connection: scope === "corporate" ? "cts" : "rts",
          signal,
        });
        const chat = chatList.chats.find(
          (candidate) => candidate.groupChatId === chatId && !candidate.left,
        );
        if (!chat) {
          throw new Error("Chat is not present in the authenticated user's active chat list");
        }
        const page = await readHistory(
          session,
          chat,
          {
            limit,
            beforeSyncId,
            signal,
          },
        );
        return jsonResult(page as unknown as JsonObject);
      } catch (error) {
        return toolError(error);
      }
    },
  );

  server.registerTool(
    "express_send_message",
    {
      title: "Send an eXpress message",
      description:
        "Encrypt and send a text message as the authenticated eXpress user. This external write is disabled unless the process owner sets EXPRESS_ENABLE_SEND=1 and must be approved by the MCP host.",
      inputSchema: z.object({
        chatId: z.string().trim().min(1).max(300),
        text: z.string().min(1).max(4_000),
        idempotencyKey: z.uuid(),
        scope: z.enum(["corporate", "personal"]).default("corporate"),
      }),
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    async ({ chatId, text, idempotencyKey, scope }, ctx) => {
      try {
        if (!allowSend) {
          throw new Error(
            "Message sending is disabled. The MCP process owner must set EXPRESS_ENABLE_SEND=1",
          );
        }
        const signal = operationSignal(ctx.mcpReq.signal);
        return await withConnectorLifecycleLock(signal, async () => {
        policy.assertAllowed("chats.discover");
        policy.assertAllowed("keys.read");
        policy.assertAllowed("message.send");
        const session = await loadScopedSession(scope, signal);
        const chatList = await fetchChats(session, {
          timeoutMs: 20_000,
          connection: scope === "corporate" ? "cts" : "rts",
          signal,
        });
        const chat = chatList.chats.find(
          (candidate) =>
            candidate.groupChatId === chatId &&
            candidate.active &&
            !candidate.left,
        );
        if (!chat) {
          throw new Error("Chat is not present in the authenticated user's active chat list");
        }
        const textHash = createHash("sha256").update(text).digest("hex");
        const principalHash = sessionPrincipalHash(session, scope);
        const expectedConfirmation: SendConfirmationState = {
          operation: "message.send",
          scope,
          principalHash,
          chatId,
          textHash,
          idempotencyKey,
        };
        const confirmationStateSchema = z.object({
          operation: z.literal("message.send"),
          scope: z.enum(["corporate", "personal"]),
          principalHash: z.string().regex(/^[0-9a-f]{64}$/),
          chatId: z.string(),
          textHash: z.string().regex(/^[0-9a-f]{64}$/),
          idempotencyKey: z.uuid(),
        });
        const stateResult = confirmationStateSchema.safeParse(
          ctx.mcpReq.requestState<SendConfirmationState>(),
        );
        const confirmation = acceptedContent(
          ctx.mcpReq.inputResponses,
          "confirm-send",
          z.object({ confirm: z.literal(true) }),
        );
        if (!stateResult.success || confirmation?.confirm !== true) {
          return inputRequired({
            requestState: await requestStateCodec.mint(expectedConfirmation, ctx),
            inputRequests: {
              "confirm-send": inputRequired.elicit({
                message:
                  "Отправить сообщение в eXpress?\n" +
                  `scope: ${scope}\n` +
                  `name: ${confirmationLiteral(chat.name ?? "")}\n` +
                  `chatId: ${confirmationLiteral(chat.groupChatId)}\n` +
                  `chatType: ${confirmationLiteral(chat.chatType ?? "unknown")}\n` +
                  `text: ${confirmationLiteral(text)}`,
                requestedSchema: {
                  type: "object",
                  properties: {
                    confirm: {
                      type: "boolean",
                      title: "Подтверждаю отправку",
                    },
                  },
                  required: ["confirm"],
                },
              }),
            },
          });
        }
        if (
          stateResult.data.operation !== expectedConfirmation.operation ||
          stateResult.data.scope !== expectedConfirmation.scope ||
          stateResult.data.principalHash !== expectedConfirmation.principalHash ||
          stateResult.data.chatId !== expectedConfirmation.chatId ||
          stateResult.data.textHash !== expectedConfirmation.textHash ||
          stateResult.data.idempotencyKey !== expectedConfirmation.idempotencyKey
        ) {
          throw new Error(
            "Send confirmation does not match the authenticated account, destination, or text",
          );
        }
        const fingerprint = createHash("sha256")
          .update(JSON.stringify({ principalHash, scope, chatId, text }))
          .digest("hex");
        const existing = sendAttempts.get(idempotencyKey);
        if (existing && existing.fingerprint !== fingerprint) {
          throw new Error("Idempotency key was already used for different message content");
        }
        const promise = existing?.promise ?? (async (): Promise<SendMessageResult> => {
          const beginResult = await sendJournal.begin(idempotencyKey, fingerprint);
          if (beginResult === "mismatch") {
            throw new Error(
              "Idempotency key was already used for different message content",
            );
          }
          if (beginResult === "uncertain") {
            throw new MessageDeliveryError(
              "unknown",
              "A previous send attempt has an uncertain outcome; reconcile the chat history before retrying",
            );
          }
          if (beginResult === "retired") {
            throw new Error(
              "Idempotency key was retired after reconciliation; use a new UUID and approve a new send",
            );
          }
          if (beginResult === "acknowledged") {
            return {
              status: "acknowledged",
              chatId,
              syncId: idempotencyKey,
              insertedAt: null,
            };
          }

          try {
            const result = await sendMessage(session, chat, text, {
              signal,
              syncId: idempotencyKey,
            });
            // The remote acknowledgement is authoritative. If this local write
            // fails, leave the durable entry pending so a later retry fails
            // closed as uncertain instead of duplicating the message.
            await sendJournal
              .acknowledge(
                idempotencyKey,
                fingerprint,
                result.insertedAt ?? undefined,
              )
              .catch(() => undefined);
            return result;
          } catch (error) {
            if (error instanceof MessageDeliveryError && error.status === "unknown") {
              await sendJournal
                .markUnknown(idempotencyKey, fingerprint)
                .catch(() => undefined);
            } else {
              await sendJournal
                .clearKnownFailure(idempotencyKey, fingerprint)
                .catch(() => undefined);
            }
            throw error;
          }
        })();
        if (!existing) {
          sendAttempts.set(idempotencyKey, {
            fingerprint,
            promise,
          });
        }
        try {
          const result = await promise;
          return jsonResult(result as unknown as JsonObject);
        } finally {
          if (sendAttempts.get(idempotencyKey)?.promise === promise) {
            sendAttempts.delete(idempotencyKey);
          }
        }
        });
      } catch (error) {
        if (error instanceof MessageDeliveryError) {
          return deliveryErrorResult(error, idempotencyKey);
        }
        return toolError(error);
      }
    },
  );

  return server;
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  serveStdio(() => createExpressMcpServer(), {
    onerror: (error) => {
      process.stderr.write(`eXpress MCP error: ${error.message}\n`);
    },
  });
}
