import { createHash, randomUUID } from "node:crypto";
import {
  chmod,
  lstat,
  mkdir,
  readFile,
  rename,
  rmdir,
  unlink,
  utimes,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";

import { APPLICATION_STORAGE_ID } from "../application-identity.js";

const OWNER_FILE = "owner.json";
const STALE_AFTER_MS = 2 * 60_000;
const HEARTBEAT_INTERVAL_MS = 20_000;
const RETRY_INTERVAL_MS = 50;
const BASE_DIRECTORY = join(
  tmpdir(),
  `${APPLICATION_STORAGE_ID}-${typeof process.getuid === "function" ? process.getuid() : "user"}-cts-refresh-locks`,
);

interface LockOwner {
  token: string;
  pid: number;
  createdAt: number;
}

function errorCode(error: unknown): string | undefined {
  return error && typeof error === "object" && "code" in error
    ? String(error.code)
    : undefined;
}

function lockName(registrationId: string): string {
  if (
    registrationId.trim() !== registrationId ||
    registrationId.length === 0 ||
    registrationId.length > 512
  ) {
    throw new TypeError("registrationId is invalid");
  }
  return `${createHash("sha256").update(registrationId, "utf8").digest("hex")}.lock`;
}

async function ensurePrivateBaseDirectory(): Promise<void> {
  try {
    await mkdir(BASE_DIRECTORY, { mode: 0o700 });
  } catch (error) {
    if (errorCode(error) !== "EEXIST") {
      throw new Error("Unable to prepare the CTS refresh lock directory");
    }
  }

  let metadata;
  try {
    metadata = await lstat(BASE_DIRECTORY);
  } catch {
    throw new Error("Unable to inspect the CTS refresh lock directory");
  }
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new Error("CTS refresh lock directory is unsafe");
  }
  if (typeof process.getuid === "function" && metadata.uid !== process.getuid()) {
    throw new Error("CTS refresh lock directory has an unexpected owner");
  }
  if (process.platform !== "win32" && (metadata.mode & 0o077) !== 0) {
    try {
      await chmod(BASE_DIRECTORY, 0o700);
    } catch {
      throw new Error("Unable to secure the CTS refresh lock directory");
    }
  }
}

async function readOwner(directory: string): Promise<LockOwner | null> {
  let raw: string;
  try {
    raw = await readFile(join(directory, OWNER_FILE), "utf8");
  } catch (error) {
    if (errorCode(error) === "ENOENT") {
      return null;
    }
    throw new Error("Unable to inspect the CTS refresh lock owner");
  }
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  const owner = value as Partial<LockOwner>;
  if (
    typeof owner.token !== "string" ||
    owner.token.length === 0 ||
    !Number.isSafeInteger(owner.pid) ||
    (owner.pid ?? 0) <= 0 ||
    !Number.isFinite(owner.createdAt)
  ) {
    return null;
  }
  return owner as LockOwner;
}

function isProcessAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return errorCode(error) !== "ESRCH";
  }
}

async function removeKnownLockDirectory(directory: string): Promise<void> {
  try {
    await unlink(join(directory, OWNER_FILE));
  } catch (error) {
    if (errorCode(error) !== "ENOENT") {
      throw new Error("Unable to remove the CTS refresh lock owner");
    }
  }
  try {
    await rmdir(directory);
  } catch (error) {
    if (errorCode(error) !== "ENOENT") {
      throw new Error("Unable to remove the CTS refresh lock directory");
    }
  }
}

async function recoverStaleLock(lockDirectory: string): Promise<boolean> {
  let metadata;
  try {
    metadata = await lstat(lockDirectory);
  } catch (error) {
    if (errorCode(error) === "ENOENT") {
      return true;
    }
    throw new Error("Unable to inspect the CTS refresh lock");
  }
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new Error("CTS refresh lock path is unsafe");
  }
  if (Date.now() - metadata.mtimeMs <= STALE_AFTER_MS) {
    return false;
  }

  const owner = await readOwner(lockDirectory);
  if (owner && isProcessAlive(owner.pid)) {
    return false;
  }

  const quarantine = `${lockDirectory}.stale-${randomUUID()}`;
  try {
    await rename(lockDirectory, quarantine);
  } catch (error) {
    if (errorCode(error) === "ENOENT") {
      return true;
    }
    throw new Error("Unable to recover the stale CTS refresh lock");
  }
  try {
    await removeKnownLockDirectory(quarantine);
  } catch {
    // The original lock name is already free. Unexpected files are deliberately
    // not removed recursively; a later maintenance pass may inspect them.
  }
  return true;
}

async function waitForRetry(signal: AbortSignal): Promise<void> {
  try {
    await delay(RETRY_INTERVAL_MS, undefined, { signal });
  } catch {
    signal.throwIfAborted();
    throw new Error("Unable to wait for the CTS refresh lock");
  }
}

async function releaseOwnedLock(
  lockDirectory: string,
  token: string,
): Promise<void> {
  const owner = await readOwner(lockDirectory);
  if (!owner || owner.token !== token) {
    return;
  }
  await removeKnownLockDirectory(lockDirectory);
}

function startHeartbeat(
  lockDirectory: string,
  token: string,
): () => Promise<void> {
  let stopped = false;
  let heartbeat: Promise<void> | null = null;
  const timer = setInterval(() => {
    if (stopped || heartbeat) {
      return;
    }
    heartbeat = (async () => {
      const owner = await readOwner(lockDirectory);
      if (!owner || owner.token !== token) {
        return;
      }
      const now = new Date();
      await utimes(lockDirectory, now, now);
    })()
      .catch(() => undefined)
      .finally(() => {
        heartbeat = null;
      });
  }, HEARTBEAT_INTERVAL_MS);
  timer.unref();
  return async () => {
    stopped = true;
    clearInterval(timer);
    if (heartbeat) {
      await heartbeat;
    }
  };
}

/**
 * Serializes CTS refreshes for one device across local Node processes.
 * The raw registration id is used only as SHA-256 input and is never stored.
 */
export async function withCtsRefreshLock<T>(
  registrationId: string,
  signal: AbortSignal,
  operation: () => Promise<T>,
): Promise<T> {
  const name = lockName(registrationId);
  if (typeof operation !== "function") {
    throw new TypeError("operation must be a function");
  }
  signal.throwIfAborted();
  await ensurePrivateBaseDirectory();
  const lockDirectory = join(BASE_DIRECTORY, name);
  const token = randomUUID();

  for (;;) {
    signal.throwIfAborted();
    try {
      await mkdir(lockDirectory, { mode: 0o700 });
    } catch (error) {
      if (errorCode(error) !== "EEXIST") {
        throw new Error("Unable to acquire the CTS refresh lock");
      }
      if (!(await recoverStaleLock(lockDirectory))) {
        await waitForRetry(signal);
      }
      continue;
    }

    const owner: LockOwner = {
      token,
      pid: process.pid,
      createdAt: Date.now(),
    };
    try {
      await writeFile(
        join(lockDirectory, OWNER_FILE),
        JSON.stringify(owner),
        { encoding: "utf8", flag: "wx", mode: 0o600 },
      );
    } catch {
      try {
        await rmdir(lockDirectory);
      } catch {
        // A later stale-recovery attempt handles an incomplete lock directory.
      }
      throw new Error("Unable to initialize the CTS refresh lock");
    }

    const stopHeartbeat = startHeartbeat(lockDirectory, token);
    let result: T | undefined;
    let operationFailed = false;
    let operationError: unknown;
    try {
      signal.throwIfAborted();
      result = await operation();
    } catch (error) {
      operationFailed = true;
      operationError = error;
    }

    await stopHeartbeat();
    let releaseError: unknown;
    try {
      await releaseOwnedLock(lockDirectory, token);
    } catch (error) {
      releaseError = error;
    }
    if (operationFailed) {
      throw operationError;
    }
    if (releaseError !== undefined) {
      throw releaseError;
    }
    return result as T;
  }
}
