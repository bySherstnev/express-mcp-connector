import type { StandaloneExpressSession } from "../auth/standalone-qr-client.js";

export type ExpressConnectionKind = "rts" | "cts";

export interface ExpressConnection {
  kind: ExpressConnectionKind;
  host: string;
  authToken: string;
  userHuid: string;
  serverId: string;
  keyPrefix: ExpressConnectionKind;
}

export function resolveExpressConnection(
  session: StandaloneExpressSession,
  kind: ExpressConnectionKind,
): ExpressConnection {
  if (kind === "cts") {
    if (!session.cts?.active || session.cts.accessToken.length === 0) {
      throw new Error(
        "Corporate eXpress session is not connected; complete CTS authentication first",
      );
    }
    return {
      kind,
      host: session.cts.host,
      authToken: session.cts.accessToken,
      userHuid: session.cts.userHuid,
      serverId: session.cts.serverId,
      keyPrefix: "cts",
    };
  }
  return {
    kind,
    host: session.rts.host,
    authToken: session.rts.authToken,
    userHuid: session.rts.userHuid,
    serverId: session.rts.serverId,
    keyPrefix: "rts",
  };
}

export function connectionKeyField(
  connection: ExpressConnection,
  suffix: "pub_key_id" | "pub_key_body" | "priv_key_body" | "key_algo",
): string {
  return `${connection.keyPrefix}_${suffix}`;
}
