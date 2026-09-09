const ALLOWED_OPERATIONS = new Set([
  "chats.discover",
  "history.read",
  "keys.read",
  "message.send",
] as const);

export type ConnectorOperation =
  | "chats.discover"
  | "history.read"
  | "keys.read"
  | "message.send";

/** Enforces the MCP connector's fail-closed capability boundary. */
export class ConnectorPolicyGuard {
  assertAllowed(operation: string): asserts operation is ConnectorOperation {
    if (!ALLOWED_OPERATIONS.has(operation as ConnectorOperation)) {
      throw new Error("Operation denied by the connector capability policy");
    }
  }
}
