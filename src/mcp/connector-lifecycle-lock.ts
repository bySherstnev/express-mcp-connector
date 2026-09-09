import { APPLICATION_STORAGE_ID } from "../application-identity.js";
import { withCtsRefreshLock } from "../auth/cts-refresh-lock.js";

const CONNECTOR_LIFECYCLE_SCOPE = `${APPLICATION_STORAGE_ID} connector lifecycle`;

/** Serializes external writes and destructive local lifecycle operations. */
export function withConnectorLifecycleLock<T>(
  signal: AbortSignal,
  operation: () => Promise<T>,
): Promise<T> {
  return withCtsRefreshLock(CONNECTOR_LIFECYCLE_SCOPE, signal, operation);
}
