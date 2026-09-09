import { randomUUID } from "node:crypto";

import sodium from "libsodium-wrappers-sumo";

import type { StandaloneExpressSession } from "../auth/standalone-qr-client.js";
import {
  connectionKeyField,
  resolveExpressConnection,
  type ExpressConnectionKind,
} from "./connection.js";
import type { DeviceChat } from "./device-chat-list.js";
import { buildDeviceSocketUrl } from "./device-socket.js";
import {
  fetchKdcPublicKeys,
  type ExpressPublicKey,
} from "./kdc-public-keys.js";
import {
  EXPRESS_SIGNING_ALGORITHM,
  isSupportedKdcKeyAlgorithm,
  resolveOutboundEventAlgorithm,
} from "./protocol-capabilities.js";

type JsonRecord = Record<string, unknown>;

export interface EncryptedTextEvent {
  group_chat_id: string;
  sync_id: string;
  payload: string;
  keys: Array<{ key_id: string; key: string; algo: string }>;
  signature: { sign: string; sign_key_id: string; sign_algo: string };
}

export interface SendMessageResult {
  status: "acknowledged";
  chatId: string;
  syncId: string;
  insertedAt: string | null;
}

export interface MessageSendDependencies {
  fetchKdcPublicKeys?: typeof fetchKdcPublicKeys;
  uuid?: () => string;
  now?: () => string;
  socketFactory?: (url: string) => WebSocket;
  syncId?: string;
  messageId?: string;
}

export type MessageDeliveryStatus = "not_sent" | "rejected" | "unknown";

export class MessageDeliveryError extends Error {
  constructor(
    readonly status: MessageDeliveryStatus,
    message: string,
  ) {
    super(message);
    this.name = "MessageDeliveryError";
  }
}

function asRecord(value: unknown): JsonRecord | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as JsonRecord)
    : null;
}

function decodeSessionKey(
  session: StandaloneExpressSession,
  field: string,
  expectedLength: number,
): Uint8Array {
  const body = session.encryptionKeys[field];
  if (typeof body !== "string" || body.length === 0) {
    throw new Error("Stored eXpress encryption keys are incomplete");
  }
  let decoded: Uint8Array;
  try {
    decoded = sodium.from_base64(body, sodium.base64_variants.ORIGINAL);
  } catch {
    throw new Error("Stored eXpress encryption keys are invalid");
  }
  if (decoded.length !== expectedLength) {
    throw new Error("Stored eXpress encryption key has an invalid length");
  }
  return decoded;
}

function concat(left: Uint8Array, right: Uint8Array): Uint8Array {
  const result = new Uint8Array(left.length + right.length);
  result.set(left);
  result.set(right, left.length);
  return result;
}

function sealSymmetricKey(
  symmetricKey: Uint8Array,
  recipientPublicKey: Uint8Array,
  senderPrivateKey: Uint8Array,
): string {
  const nonce = sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES);
  const ciphertext = sodium.crypto_box_easy(
    symmetricKey,
    nonce,
    recipientPublicKey,
    senderPrivateKey,
  );
  return sodium.to_base64(
    concat(nonce, ciphertext),
    sodium.base64_variants.ORIGINAL,
  );
}

export async function composeEncryptedTextEvent(
  session: StandaloneExpressSession,
  chat: DeviceChat,
  text: string,
  publicKeys: ReadonlyMap<string, ExpressPublicKey>,
  options: {
    uuid?: () => string;
    now?: () => string;
    syncId?: string;
    messageId?: string;
  } = {},
): Promise<EncryptedTextEvent> {
  await sodium.ready;
  const signingConnections = session.requestSigning?.uploadedConnections;
  if (
    !session.requestSigning?.uploaded ||
    signingConnections?.includes(chat.connection) !== true
  ) {
    throw new Error("eXpress request signing identity is not ready");
  }
  if (!chat.active || chat.left) {
    throw new Error("Cannot send to an inactive eXpress chat");
  }
  const outboundEventAlgorithm = resolveOutboundEventAlgorithm(
    chat.encryptionAlgorithm,
  );
  if (!outboundEventAlgorithm) {
    throw new Error("Unsupported eXpress chat encryption profile");
  }
  if (text.trim().length === 0 || text.length > 4_000) {
    throw new RangeError("Message text must contain 1 to 4000 characters");
  }
  const connection = resolveExpressConnection(session, chat.connection);
  const ownPublicKeyId =
    session.encryptionKeys[connectionKeyField(connection, "pub_key_id")];
  const ownPublicKeyBody =
    session.encryptionKeys[connectionKeyField(connection, "pub_key_body")];
  if (
    typeof ownPublicKeyId !== "string" ||
    typeof ownPublicKeyBody !== "string"
  ) {
    throw new Error("Stored eXpress encryption keys are incomplete");
  }
  if (
    !isSupportedKdcKeyAlgorithm(
      session.encryptionKeys[connectionKeyField(connection, "key_algo")],
    )
  ) {
    throw new Error("Unsupported eXpress device encryption algorithm");
  }
  if (session.requestSigning.algorithm !== EXPRESS_SIGNING_ALGORITHM) {
    throw new Error("Unsupported eXpress signing algorithm");
  }
  const recipientIds = [...new Set(chat.encryptionKeyIds)];
  const uniqueRecipientIds = [...new Set(recipientIds)];
  if (uniqueRecipientIds.length === 0) {
    throw new Error("Chat has no recipient encryption keys");
  }

  const senderPrivateKey = decodeSessionKey(
    session,
    connectionKeyField(connection, "priv_key_body"),
    sodium.crypto_box_SECRETKEYBYTES,
  );
  const signingPrivateKey = (() => {
    try {
      return sodium.from_base64(
        session.requestSigning!.privateKey,
        sodium.base64_variants.ORIGINAL,
      );
    } catch {
      throw new Error("Stored eXpress signing key is invalid");
    }
  })();
  if (signingPrivateKey.length !== sodium.crypto_sign_SECRETKEYBYTES) {
    sodium.memzero(senderPrivateKey);
    sodium.memzero(signingPrivateKey);
    throw new Error("Stored eXpress signing key has an invalid length");
  }

  const symmetricKey = sodium.randombytes_buf(
    sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
  );
  const uuid = options.uuid ?? randomUUID;
  const syncId = options.syncId ?? uuid();
  const plaintext = {
    type: "text",
    msg_id: options.messageId ?? uuid(),
    from: connection.userHuid,
    timestamp: (options.now ?? (() => new Date().toISOString()))(),
    group_chat_id: chat.groupChatId,
    lat: 0,
    lng: 0,
    link_meta_disabled: true,
    stealth_forwarding: false,
    body: text,
  };

  let plaintextBytes: Uint8Array | undefined;
  try {
    const nonce = sodium.randombytes_buf(
      sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
    );
    plaintextBytes = sodium.from_string(JSON.stringify(plaintext));
    const encryptedPayload = sodium.to_base64(
      concat(
        nonce,
        sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
          plaintextBytes,
          sodium.from_string(`${chat.groupChatId}:${syncId}`),
          null,
          nonce,
          symmetricKey,
        ),
      ),
      sodium.base64_variants.ORIGINAL,
    );
    const keys = uniqueRecipientIds.map((keyId) => {
      const externalKey =
        keyId === ownPublicKeyId ? undefined : publicKeys.get(keyId);
      const keyBody =
        keyId === ownPublicKeyId ? ownPublicKeyBody : externalKey?.body;
      if (!keyBody) {
        throw new Error("A recipient encryption key is unavailable");
      }
      if (
        externalKey &&
        !isSupportedKdcKeyAlgorithm(externalKey.algo)
      ) {
        throw new Error("A recipient uses an unsupported encryption algorithm");
      }
      let publicKey: Uint8Array;
      try {
        publicKey = sodium.from_base64(
          keyBody,
          sodium.base64_variants.ORIGINAL,
        );
      } catch {
        throw new Error("A recipient encryption key is invalid");
      }
      if (publicKey.length !== sodium.crypto_box_PUBLICKEYBYTES) {
        throw new Error("A recipient encryption key has an invalid length");
      }
      return {
        key_id: keyId,
        key: sealSymmetricKey(symmetricKey, publicKey, senderPrivateKey),
        algo: outboundEventAlgorithm,
      };
    });
    return {
      group_chat_id: chat.groupChatId,
      sync_id: syncId,
      payload: encryptedPayload,
      keys,
      signature: {
        sign: sodium.to_base64(
          sodium.crypto_sign_detached(encryptedPayload, signingPrivateKey),
          sodium.base64_variants.ORIGINAL,
        ),
        sign_key_id: session.requestSigning.publicKeyId,
        sign_algo: session.requestSigning.algorithm,
      },
    };
  } finally {
    sodium.memzero(senderPrivateKey);
    sodium.memzero(signingPrivateKey);
    sodium.memzero(symmetricKey);
    if (plaintextBytes) {
      sodium.memzero(plaintextBytes);
    }
  }
}

export async function sendSocketEvent(
  session: StandaloneExpressSession,
  event: EncryptedTextEvent,
  connectionKind: ExpressConnectionKind,
  options: { socketFactory?: (url: string) => WebSocket; signal?: AbortSignal },
): Promise<SendMessageResult> {
  const connection = resolveExpressConnection(session, connectionKind);
  const socket = (options.socketFactory ?? ((url) => new WebSocket(url)))(
    buildDeviceSocketUrl(session, randomUUID(), connectionKind),
  );
  const signal = options.signal ?? AbortSignal.timeout(30_000);
  try {
    return await new Promise<SendMessageResult>((resolve, reject) => {
      let dispatched = false;
      let settled = false;
      const cleanup = (): void => signal.removeEventListener("abort", abort);
      const fail = (status: MessageDeliveryStatus, message: string): void => {
        if (settled) {
          return;
        }
        settled = true;
        cleanup();
        reject(new MessageDeliveryError(status, message));
      };
      const abort = (): void =>
        fail(
          dispatched ? "unknown" : "not_sent",
          dispatched
            ? "eXpress message send outcome is unknown after timeout"
            : "eXpress message was not sent before timeout",
        );
      signal.addEventListener("abort", abort, { once: true });
      if (signal.aborted) {
        abort();
        return;
      }
      socket.addEventListener("open", () => {
        try {
          socket.send(JSON.stringify({
            topic: "phoenix",
            event: "authenticate",
            payload: { token: connection.authToken },
            ref: 0,
          }));
        } catch {
          fail("not_sent", "Device socket authentication send failed");
        }
      });
      socket.addEventListener("message", (message) => {
        if (typeof message.data !== "string") {
          return;
        }
        let frame: JsonRecord | null;
        try {
          frame = asRecord(JSON.parse(message.data));
        } catch {
          return;
        }
        if (!frame) {
          return;
        }
        const payload = asRecord(frame.payload);
        if (frame.ref === 0) {
          if (payload?.status !== "ok") {
            fail("not_sent", "Device socket authentication was rejected");
            return;
          }
          try {
            socket.send(JSON.stringify({
              topic: `groupchat:${event.group_chat_id}`,
              event: "message_new",
              payload: event,
              ref: 1,
            }));
            dispatched = true;
          } catch {
            fail("not_sent", "Device socket message send failed");
          }
          return;
        }
        if (frame.ref !== 1) {
          return;
        }
        if (payload?.status === "error") {
          fail("rejected", "eXpress rejected the message");
          return;
        }
        if (payload?.status !== "ok") {
          fail(
            "unknown",
            "eXpress returned an unrecognized acknowledgement after sending",
          );
          return;
        }
        const response = asRecord(payload.response);
        if (settled) {
          return;
        }
        settled = true;
        cleanup();
        resolve({
          status: "acknowledged",
          chatId: event.group_chat_id,
          syncId: event.sync_id,
          insertedAt:
            response && typeof response.inserted_at === "string"
              ? response.inserted_at
              : null,
        });
      });
      socket.addEventListener("error", () =>
        fail(
          dispatched ? "unknown" : "not_sent",
          "Device socket connection failed",
        ),
      );
      socket.addEventListener("close", () =>
        fail(
          dispatched ? "unknown" : "not_sent",
          "Device socket closed before confirming the message",
        ),
      );
    });
  } finally {
    socket.close();
  }
}

export async function sendEncryptedTextMessage(
  session: StandaloneExpressSession,
  chat: DeviceChat,
  text: string,
  options: MessageSendDependencies & { signal?: AbortSignal } = {},
): Promise<SendMessageResult> {
  const connection = resolveExpressConnection(session, chat.connection);
  const ownPublicKeyId =
    session.encryptionKeys[connectionKeyField(connection, "pub_key_id")];
  const ids = chat.encryptionKeyIds.filter((id) => id !== ownPublicKeyId);
  const publicKeys =
    ids.length === 0
      ? new Map<string, ExpressPublicKey>()
      : await (options.fetchKdcPublicKeys ?? fetchKdcPublicKeys)(session, ids, {
          signal: options.signal,
          connection: chat.connection,
        });
  const event = await composeEncryptedTextEvent(session, chat, text, publicKeys, {
    uuid: options.uuid,
    now: options.now,
    syncId: options.syncId,
    messageId: options.messageId,
  });
  return sendSocketEvent(session, event, chat.connection, options);
}
