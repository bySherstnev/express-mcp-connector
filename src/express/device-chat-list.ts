import { randomUUID } from "node:crypto";

import type { StandaloneExpressSession } from "../auth/standalone-qr-client.js";
import {
  resolveExpressConnection,
  type ExpressConnectionKind,
} from "./connection.js";
import { buildDeviceSocketUrl } from "./device-socket.js";

type JsonRecord = Record<string, unknown>;

export interface DeviceChat {
  connection: ExpressConnectionKind;
  groupChatId: string;
  name: string | null;
  chatType: string | null;
  encryptionKeyIds: string[];
  encryptionAlgorithm: string | null;
  active: boolean;
  left: boolean;
  sharedHistory: boolean | null;
  lastEventSyncId: string | null;
  lastEventInsertedAt: string | null;
  lastIgnoreMessagesAt: string | null;
}

export interface DeviceChatList {
  chats: DeviceChat[];
  generatedAt: string | null;
}

function asRecord(value: unknown): JsonRecord | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as JsonRecord)
    : null;
}

function optionalString(record: JsonRecord, field: string): string | null {
  return typeof record[field] === "string" ? record[field] : null;
}

export function normalizeDeviceChat(
  value: unknown,
  connection: ExpressConnectionKind = "rts",
): DeviceChat {
  const chat = asRecord(value);
  if (!chat || typeof chat.group_chat_id !== "string") {
    throw new Error("Device socket returned an invalid chat");
  }
  const settings = asRecord(chat.chat_settings);
  return {
    connection,
    groupChatId: chat.group_chat_id,
    name: optionalString(chat, "name"),
    chatType: optionalString(chat, "chat_type"),
    encryptionKeyIds: Array.isArray(chat.keys)
      ? chat.keys.filter((key): key is string => typeof key === "string")
      : [],
    encryptionAlgorithm: optionalString(chat, "algo"),
    active: chat.active === true,
    left: chat.left === true,
    sharedHistory:
      typeof chat.shared_history === "boolean" ? chat.shared_history : null,
    lastEventSyncId: optionalString(chat, "last_event_sync_id"),
    lastEventInsertedAt: optionalString(chat, "last_event_inserted_at"),
    lastIgnoreMessagesAt: settings
      ? optionalString(settings, "last_ignore_messages_at")
      : null,
  };
}

/** Fetches the initial chat list through the authenticated Phoenix device socket. */
export async function fetchDeviceChatList(
  session: StandaloneExpressSession,
  options: {
    timeoutMs?: number;
    connection?: ExpressConnectionKind;
    signal?: AbortSignal;
  } = {},
): Promise<DeviceChatList> {
  const timeoutMs = options.timeoutMs ?? 20_000;
  const connectionKind = options.connection ?? "rts";
  const connection = resolveExpressConnection(session, connectionKind);
  const socket = new WebSocket(
    buildDeviceSocketUrl(session, randomUUID(), connectionKind),
  );
  try {
    return await new Promise<DeviceChatList>((resolve, reject) => {
      let settled = false;
      const timeout = setTimeout(
        () => fail("Device chat list request timed out"),
        timeoutMs,
      );
      const fail = (message: string): void => {
        if (settled) {
          return;
        }
        settled = true;
        clearTimeout(timeout);
        reject(new Error(message));
      };
      const send = (value: JsonRecord): boolean => {
        try {
          socket.send(JSON.stringify(value));
          return true;
        } catch {
          fail("Device socket send failed");
          return false;
        }
      };
      const abort = (): void => fail("Device chat list request was cancelled");
      options.signal?.addEventListener("abort", abort, { once: true });
      if (options.signal?.aborted) {
        abort();
        return;
      }
      socket.addEventListener("open", () => {
        send({
          topic: "phoenix",
          event: "authenticate",
          payload: { token: connection.authToken },
          ref: 0,
        });
      });
      socket.addEventListener("message", (event) => {
        if (typeof event.data !== "string") {
          return;
        }
        let frame: JsonRecord | null;
        try {
          frame = asRecord(JSON.parse(event.data));
        } catch {
          return;
        }
        if (!frame) {
          return;
        }
        const payload = asRecord(frame.payload);
        if (frame.ref === 0) {
          if (payload?.status !== "ok") {
            fail("Device socket authentication was rejected");
            return;
          }
          send({
            topic: "system",
            event: "chat_list",
            payload: { since: null, request_version: 6 },
            ref: 1,
          });
          return;
        }
        if (frame.ref !== 1) {
          return;
        }
        if (payload?.status !== "ok") {
          fail("Device chat list request was rejected");
          return;
        }
        const response = asRecord(payload.response);
        if (!response || !Array.isArray(response.chat_list)) {
          fail("Device socket returned an invalid chat list");
          return;
        }
        let chats: DeviceChat[];
        try {
          chats = response.chat_list.map((chat) =>
            normalizeDeviceChat(chat, connectionKind),
          );
        } catch {
          fail("Device socket returned an invalid chat list");
          return;
        }
        if (settled) {
          return;
        }
        settled = true;
        clearTimeout(timeout);
        options.signal?.removeEventListener("abort", abort);
        resolve({
          chats,
          generatedAt: optionalString(response, "generated_at"),
        });
      });
      socket.addEventListener("error", () =>
        fail("Device socket connection failed"),
      );
      socket.addEventListener("close", () =>
        fail("Device socket closed before returning chats"),
      );
    });
  } finally {
    socket.close();
  }
}
