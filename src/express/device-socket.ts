import { randomUUID } from "node:crypto";

import type { StandaloneExpressSession } from "../auth/standalone-qr-client.js";
import {
  connectionKeyField,
  resolveExpressConnection,
  type ExpressConnectionKind,
} from "./connection.js";

function requiredEncryptionKey(
  session: StandaloneExpressSession,
  field: string,
): string {
  const value = session.encryptionKeys[field];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error("Stored eXpress encryption keys are incomplete");
  }
  return value;
}

export function buildDeviceSocketUrl(
  session: StandaloneExpressSession,
  instanceId = randomUUID(),
  connectionKind: ExpressConnectionKind = "rts",
): string {
  const connection = resolveExpressConnection(session, connectionKind);
  const url = new URL(`wss://${connection.host}/socket/user/websocket`);
  url.searchParams.set("vsn", "1.0.0");
  url.searchParams.set("auto_join", "true");
  url.searchParams.set(
    "key_id",
    requiredEncryptionKey(
      session,
      connectionKeyField(connection, "pub_key_id"),
    ),
  );
  url.searchParams.set("version", "6");
  url.searchParams.set("background", "false");
  url.searchParams.set("voex_unencrypted", "true");
  url.searchParams.set("voex_multistream", "true");
  url.searchParams.set("voex_audio_bridge", "true");
  url.searchParams.set("instance_id", instanceId);
  return url.toString();
}
