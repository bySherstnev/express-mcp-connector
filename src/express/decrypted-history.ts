import sodium from "libsodium-wrappers-sumo";

import type { StandaloneExpressSession } from "../auth/standalone-qr-client.js";
import { decryptExpress372Payload } from "../crypto/express-372-decrypt.js";
import {
  connectionKeyField,
  resolveExpressConnection,
} from "./connection.js";
import type { DeviceChat } from "./device-chat-list.js";
import { fetchEventInfo } from "./event-info-client.js";
import { fetchHistoryPage, type RawHistoryPage } from "./history-client.js";
import {
  fetchKdcPublicKeys,
  type ExpressPublicKey,
} from "./kdc-public-keys.js";
import {
  isSupportedEventAlgorithm,
  isSupportedKdcKeyAlgorithm,
} from "./protocol-capabilities.js";
import { fetchExpressUserProfiles } from "./user-profile-client.js";

type JsonRecord = Record<string, unknown>;

export interface DecryptedForwardSource {
  hidden: boolean;
  senderId: string | null;
  senderName: string | null;
  connection: "rts" | "cts" | null;
  chatId: string | null;
  chatName: string | null;
  messageSyncId: string | null;
  insertedAt: string | null;
}

export interface DecryptedHistoryMessage {
  syncId: string;
  eventType: string;
  insertedAt: string | null;
  messageId: string | null;
  senderId: string | null;
  senderName: string | null;
  kind: string | null;
  body: string | null;
  replyToMessageId: string | null;
  attachmentFileId: string | null;
  forwardedFrom: DecryptedForwardSource | null;
  status:
    | "decrypted"
    | "deleted"
    | "missing_key"
    | "malformed"
    | "unsupported_algorithm"
    | "authentication_failed"
    | "system";
}

export interface DecryptedHistoryPage {
  chatId: string;
  chatName: string | null;
  messages: DecryptedHistoryMessage[];
  unavailableCount: number;
  nextBeforeSyncId: string | null;
  generatedAt: string | null;
  anchorExcluded: boolean;
  anchorUnavailable: boolean;
}

export interface DecryptedHistoryDependencies {
  fetchHistoryPage?: typeof fetchHistoryPage;
  fetchKdcPublicKeys?: typeof fetchKdcPublicKeys;
  fetchEventInfo?: typeof fetchEventInfo;
  fetchUserProfiles?: typeof fetchExpressUserProfiles;
}

function asRecord(value: unknown): JsonRecord | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as JsonRecord)
    : null;
}

function optionalString(record: JsonRecord | null, field: string): string | null {
  return record && typeof record[field] === "string"
    ? (record[field] as string)
    : null;
}

function normalizeForwardSource(decoded: JsonRecord): DecryptedForwardSource | null {
  const forward = asRecord(decoded.forward);
  if (!forward) {
    return null;
  }
  const hidden = forward.stealth === true || decoded.stealth_forwarding === true;
  if (hidden) {
    return {
      hidden: true,
      senderId: null,
      senderName: null,
      connection: null,
      chatId: null,
      chatName: null,
      messageSyncId: null,
      insertedAt: null,
    };
  }
  const connection = optionalString(forward, "sender_conn_type");
  return {
    hidden: false,
    senderId: optionalString(forward, "sender_huid"),
    senderName: null,
    connection: connection === "rts" || connection === "cts" ? connection : null,
    chatId: optionalString(forward, "group_chat_id"),
    chatName: optionalString(forward, "source_name"),
    messageSyncId: optionalString(forward, "sync_id"),
    insertedAt: optionalString(forward, "inserted_at"),
  };
}

function normalizePlaintextMessage(
  event: JsonRecord,
  plaintext: unknown,
  expectedGroupChatId: string,
): DecryptedHistoryMessage | null {
  const decoded = asRecord(plaintext);
  const syncId = optionalString(event, "sync_id");
  if (!decoded || !syncId) {
    return null;
  }
  const claimedGroupChatId = optionalString(decoded, "group_chat_id");
  if (claimedGroupChatId && claimedGroupChatId !== expectedGroupChatId) {
    return null;
  }
  const reply = asRecord(decoded.reply);
  const claimedSenderId = optionalString(decoded, "from");
  return {
    syncId,
    eventType: optionalString(event, "event_type") ?? "message_new",
    insertedAt:
      optionalString(event, "inserted_at") ?? optionalString(decoded, "timestamp"),
    messageId: optionalString(decoded, "msg_id"),
    // `from` is part of the successfully authenticated encrypted payload. The
    // KDC key owner is a transport identity and can be shared by messages from
    // multiple users in corporate history, so it must not be used as author.
    senderId: claimedSenderId,
    senderName: null,
    kind: optionalString(decoded, "type"),
    body: optionalString(decoded, "body"),
    replyToMessageId:
      optionalString(reply, "msg_id") ?? optionalString(decoded, "reply"),
    attachmentFileId: optionalString(decoded, "link_file_id"),
    forwardedFrom: normalizeForwardSource(decoded),
    status: "decrypted",
  };
}

function findContinuationSyncId(events: readonly JsonRecord[]): string | null {
  for (let index = events.length - 1; index >= 0; index -= 1) {
    const event = events[index]!;
    const syncId = optionalString(event, "sync_id");
    if (syncId) {
      return syncId;
    }
  }
  return null;
}

function unavailableMessage(
  event: JsonRecord,
  status: Exclude<DecryptedHistoryMessage["status"], "decrypted">,
): DecryptedHistoryMessage | null {
  const syncId = optionalString(event, "sync_id");
  if (!syncId) {
    return null;
  }
  return {
    syncId,
    eventType: optionalString(event, "event_type") ?? "unknown",
    insertedAt: optionalString(event, "inserted_at"),
    messageId: null,
    senderId: null,
    senderName: null,
    kind: null,
    body: null,
    replyToMessageId: null,
    attachmentFileId: null,
    forwardedFrom: null,
    status,
  };
}

/**
 * Decrypts a bounded eXpress history page and deliberately discards raw
 * envelopes, ciphertext, signing material and unrelated payload fields.
 */
export async function decryptHistoryEvents(
  session: StandaloneExpressSession,
  chat: DeviceChat,
  page: RawHistoryPage,
  publicKeys: ReadonlyMap<string, ExpressPublicKey>,
): Promise<DecryptedHistoryPage> {
  await sodium.ready;
  const connection = resolveExpressConnection(session, chat.connection);
  const privateKeyBody =
    session.encryptionKeys[connectionKeyField(connection, "priv_key_body")];
  if (typeof privateKeyBody !== "string" || privateKeyBody.length === 0) {
    throw new Error("Stored eXpress encryption keys are incomplete");
  }
  let recipientPrivateKey: Uint8Array;
  try {
    recipientPrivateKey = sodium.from_base64(
      privateKeyBody,
      sodium.base64_variants.ORIGINAL,
    );
  } catch {
    throw new Error("Stored eXpress encryption keys are invalid");
  }

  const messages: DecryptedHistoryMessage[] = [];
  let unavailableCount = 0;
  try {
    for (const event of page.events) {
      if (event.event_type !== "message_new") {
        const message = unavailableMessage(event, "system");
        if (message) {
          messages.push(message);
        } else {
          unavailableCount += 1;
        }
        continue;
      }

      const envelope = asRecord(event.key);
      const senderKeyId = optionalString(event, "sender_key_id");
      const senderKey = senderKeyId ? publicKeys.get(senderKeyId) : undefined;
      const encryptedEnvelope = optionalString(envelope, "key");
      const encryptedPayload = optionalString(event, "payload");
      const groupChatId = optionalString(event, "group_chat_id");
      const syncId = optionalString(event, "sync_id");
      if (!groupChatId || groupChatId !== chat.groupChatId || !syncId) {
        unavailableCount += 1;
        continue;
      }
      if (!encryptedPayload) {
        const deleted = unavailableMessage(
          event,
          "deleted",
        );
        if (deleted) {
          messages.push(deleted);
        }
        continue;
      }
      if (!senderKey) {
        const missingKey = unavailableMessage(event, "missing_key");
        if (missingKey) {
          messages.push(missingKey);
        }
        unavailableCount += 1;
        continue;
      }
      const envelopeAlgorithm = optionalString(envelope, "algo");
      if (
        !isSupportedKdcKeyAlgorithm(senderKey.algo) ||
        !isSupportedEventAlgorithm(envelopeAlgorithm)
      ) {
        const unsupported = unavailableMessage(
          event,
          "unsupported_algorithm",
        );
        if (unsupported) {
          messages.push(unsupported);
        }
        unavailableCount += 1;
        continue;
      }
      if (!encryptedEnvelope) {
        const malformed = unavailableMessage(
          event,
          "malformed",
        );
        if (malformed) {
          messages.push(malformed);
        }
        unavailableCount += 1;
        continue;
      }

      try {
        const plaintext = await decryptExpress372Payload({
          encryptedEnvelope,
          encryptedPayload,
          recipientPrivateKey,
          senderPublicKey: sodium.from_base64(
            senderKey.body,
            sodium.base64_variants.ORIGINAL,
          ),
          groupChatId,
          syncId,
        });
        const message = normalizePlaintextMessage(
          event,
          plaintext,
          chat.groupChatId,
        );
        if (message) {
          messages.push(message);
        } else {
          const malformed = unavailableMessage(
            event,
            "malformed",
          );
          if (malformed) {
            messages.push(malformed);
          }
          unavailableCount += 1;
        }
      } catch {
        const failed = unavailableMessage(
          event,
          "authentication_failed",
        );
        if (failed) {
          messages.push(failed);
        }
        unavailableCount += 1;
      }
    }
  } finally {
    sodium.memzero(recipientPrivateKey);
  }

  return {
    chatId: chat.groupChatId,
    chatName: chat.name,
    messages,
    unavailableCount,
    nextBeforeSyncId: findContinuationSyncId(page.events),
    generatedAt: page.generatedAt,
    anchorExcluded: true,
    anchorUnavailable: false,
  };
}

export async function readDecryptedHistory(
  session: StandaloneExpressSession,
  chat: DeviceChat,
  input: { limit: number; beforeSyncId?: string; signal?: AbortSignal },
  dependencies: DecryptedHistoryDependencies = {},
): Promise<DecryptedHistoryPage> {
  const anchor = input.beforeSyncId ?? chat.lastEventSyncId;
  if (!anchor) {
    return {
      chatId: chat.groupChatId,
      chatName: chat.name,
      messages: [],
      unavailableCount: 0,
      nextBeforeSyncId: null,
      generatedAt: null,
      anchorExcluded: input.beforeSyncId !== undefined,
      anchorUnavailable: false,
    };
  }
  const fetchPage = dependencies.fetchHistoryPage ?? fetchHistoryPage;
  const includeCurrentAnchor = input.beforeSyncId === undefined;
  const historyLimit = includeCurrentAnchor ? Math.max(0, input.limit - 1) : input.limit;
  const historyPage =
    historyLimit === 0
      ? { events: [], generatedAt: null }
      : await fetchPage(
          session,
          {
            groupChatId: chat.groupChatId,
            direction: "backward",
            limit: historyLimit,
            syncId: anchor,
            lastIgnoreMessagesAt: chat.lastIgnoreMessagesAt,
          },
          { signal: input.signal, connection: chat.connection },
        );
  let anchorUnavailable = false;
  let anchorEvents: JsonRecord[] = [];
  if (includeCurrentAnchor) {
    try {
      anchorEvents = await (dependencies.fetchEventInfo ?? fetchEventInfo)(
        session,
        [anchor],
        { signal: input.signal, connection: chat.connection },
      );
    } catch (error) {
      if (input.signal?.aborted) {
        throw error;
      }
      anchorUnavailable = true;
    }
  }
  const page: RawHistoryPage = {
    ...historyPage,
    events: [
      ...anchorEvents.filter(
        (event) =>
          optionalString(event, "group_chat_id") === chat.groupChatId &&
          !historyPage.events.some(
            (historyEvent) =>
              optionalString(historyEvent, "sync_id") ===
              optionalString(event, "sync_id"),
          ),
      ),
      ...historyPage.events,
    ].slice(0, input.limit),
  };
  const senderKeyIds = page.events
    .map((event) => optionalString(event, "sender_key_id"))
    .filter((value): value is string => value !== null);
  const keys =
    senderKeyIds.length === 0
      ? new Map<string, ExpressPublicKey>()
      : await (dependencies.fetchKdcPublicKeys ?? fetchKdcPublicKeys)(
          session,
          senderKeyIds,
          { signal: input.signal, connection: chat.connection },
        );
  const result = await decryptHistoryEvents(session, chat, page, keys);
  const senderIdsByConnection = new Map<"rts" | "cts", Set<string>>();
  const addSenderId = (connection: "rts" | "cts", senderId: string | null) => {
    if (!senderId) {
      return;
    }
    const ids = senderIdsByConnection.get(connection) ?? new Set<string>();
    ids.add(senderId);
    senderIdsByConnection.set(connection, ids);
  };
  for (const message of result.messages) {
    if (message.status !== "decrypted") {
      continue;
    }
    addSenderId(chat.connection, message.senderId);
    if (message.forwardedFrom && !message.forwardedFrom.hidden) {
      addSenderId(
        message.forwardedFrom.connection ?? chat.connection,
        message.forwardedFrom.senderId,
      );
    }
  }
  for (const [connection, senderIds] of senderIdsByConnection) {
    try {
      const profiles = await (
        dependencies.fetchUserProfiles ?? fetchExpressUserProfiles
      )(session, [...senderIds], {
        signal: input.signal,
        connection,
      });
      for (const message of result.messages) {
        if (connection === chat.connection && message.senderId) {
          message.senderName = profiles.get(message.senderId)?.name ?? null;
        }
        const forwarded = message.forwardedFrom;
        if (
          forwarded &&
          !forwarded.hidden &&
          (forwarded.connection ?? chat.connection) === connection &&
          forwarded.senderId
        ) {
          forwarded.senderName = profiles.get(forwarded.senderId)?.name ?? null;
        }
      }
    } catch (error) {
      if (input.signal?.aborted) {
        throw error;
      }
      // History remains useful when the directory is temporarily unavailable.
      // Null is explicit and callers must never infer or invent a sender name.
    }
  }
  result.anchorExcluded = !includeCurrentAnchor;
  result.anchorUnavailable = anchorUnavailable;
  return result;
}
