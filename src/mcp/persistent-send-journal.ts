import { randomUUID } from "node:crypto";
import {
  chmod,
  lstat,
  mkdir,
  open,
  readFile,
  rename,
  unlink,
} from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";

import { APPLICATION_STORAGE_ID } from "../application-identity.js";
import { withCtsRefreshLock } from "../auth/cts-refresh-lock.js";

const JOURNAL_VERSION = 1;
const JOURNAL_FILE_NAME = "send-idempotency.json";
const JOURNAL_LOCK_SCOPE = `${APPLICATION_STORAGE_ID} persistent send journal`;
const DEFAULT_TTL_MS = 24 * 60 * 60 * 1_000;
const DEFAULT_MAX_ENTRIES = 1_000;
const MAX_JOURNAL_BYTES = 1_000_000;

export type PersistentSendState =
  | "pending"
  | "acknowledged"
  | "unknown"
  | "retired";
export type BeginSendResult =
  | "new"
  | "acknowledged"
  | "uncertain"
  | "retired"
  | "mismatch";
export type ReconcileSendOutcome = "delivered" | "not_delivered";

interface PersistentSendEntry {
  idempotencyKey: string;
  fingerprint: string;
  state: PersistentSendState;
  timestamp: number;
  insertedAt?: string;
}

interface PersistentSendJournalFile {
  version: 1;
  entries: PersistentSendEntry[];
}

export interface PersistentSendJournalOptions {
  filePath?: string;
  now?: () => number;
  ttlMs?: number;
  maxEntries?: number;
}

function errorCode(error: unknown): string | undefined {
  return error && typeof error === "object" && "code" in error
    ? String(error.code)
    : undefined;
}

function defaultStateDirectory(): string {
  if (process.platform === "win32") {
    const localAppData = process.env.LOCALAPPDATA?.trim();
    return join(
      localAppData && isAbsolute(localAppData)
        ? localAppData
        : join(homedir(), "AppData", "Local"),
      APPLICATION_STORAGE_ID,
    );
  }
  if (process.platform === "darwin") {
    return join(
      homedir(),
      "Library",
      "Application Support",
      APPLICATION_STORAGE_ID,
    );
  }
  const xdgStateHome = process.env.XDG_STATE_HOME?.trim();
  return join(
    xdgStateHome && isAbsolute(xdgStateHome)
      ? xdgStateHome
      : join(homedir(), ".local", "state"),
    APPLICATION_STORAGE_ID,
  );
}

export function defaultPersistentSendJournalPath(): string {
  return join(defaultStateDirectory(), JOURNAL_FILE_NAME);
}

function validateIdempotencyKey(value: string): void {
  if (
    value.trim() !== value ||
    value.length === 0 ||
    value.length > 200 ||
    /[\u0000-\u001f\u007f]/.test(value)
  ) {
    throw new TypeError("idempotencyKey is invalid");
  }
}

function validateFingerprint(value: string): void {
  if (!/^[0-9a-f]{64}$/i.test(value)) {
    throw new TypeError("fingerprint must be a SHA-256 hex digest");
  }
}

function validateInsertedAt(value: string | undefined): void {
  if (
    value !== undefined &&
    (value.length === 0 || value.length > 100 || !Number.isFinite(Date.parse(value)))
  ) {
    throw new TypeError("insertedAt is invalid");
  }
}

function parseEntry(value: unknown): PersistentSendEntry {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Stored send idempotency journal is invalid");
  }
  const entry = value as Partial<PersistentSendEntry>;
  const allowedFields = new Set([
    "idempotencyKey",
    "fingerprint",
    "state",
    "timestamp",
    "insertedAt",
  ]);
  if (
    Object.keys(entry).some((field) => !allowedFields.has(field)) ||
    typeof entry.idempotencyKey !== "string" ||
    typeof entry.fingerprint !== "string" ||
    (entry.state !== "pending" &&
      entry.state !== "acknowledged" &&
      entry.state !== "unknown" &&
      entry.state !== "retired") ||
    typeof entry.timestamp !== "number" ||
    !Number.isSafeInteger(entry.timestamp) ||
    entry.timestamp < 0 ||
    (entry.insertedAt !== undefined && typeof entry.insertedAt !== "string")
  ) {
    throw new Error("Stored send idempotency journal is invalid");
  }
  try {
    validateIdempotencyKey(entry.idempotencyKey);
    validateFingerprint(entry.fingerprint);
    validateInsertedAt(entry.insertedAt);
  } catch {
    throw new Error("Stored send idempotency journal is invalid");
  }
  return {
    idempotencyKey: entry.idempotencyKey,
    fingerprint: entry.fingerprint.toLowerCase(),
    state: entry.state,
    timestamp: entry.timestamp,
    ...(entry.insertedAt === undefined ? {} : { insertedAt: entry.insertedAt }),
  };
}

function parseJournal(raw: string, maxEntries: number): PersistentSendJournalFile {
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    throw new Error("Stored send idempotency journal is invalid");
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Stored send idempotency journal is invalid");
  }
  const file = value as Partial<PersistentSendJournalFile>;
  if (
    Object.keys(file).some((field) => field !== "version" && field !== "entries") ||
    file.version !== JOURNAL_VERSION ||
    !Array.isArray(file.entries) ||
    file.entries.length > maxEntries
  ) {
    throw new Error("Stored send idempotency journal is invalid");
  }
  const entries = file.entries.map(parseEntry);
  if (new Set(entries.map(({ idempotencyKey }) => idempotencyKey)).size !== entries.length) {
    throw new Error("Stored send idempotency journal is invalid");
  }
  return { version: JOURNAL_VERSION, entries };
}

async function ensurePrivateDirectory(directory: string): Promise<void> {
  try {
    await mkdir(directory, { recursive: true, mode: 0o700 });
  } catch {
    throw new Error("Unable to prepare the send idempotency journal directory");
  }
  let metadata;
  try {
    metadata = await lstat(directory);
  } catch {
    throw new Error("Unable to inspect the send idempotency journal directory");
  }
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new Error("Send idempotency journal directory is unsafe");
  }
  if (typeof process.getuid === "function" && metadata.uid !== process.getuid()) {
    throw new Error("Send idempotency journal directory has an unexpected owner");
  }
  if (process.platform !== "win32" && (metadata.mode & 0o077) !== 0) {
    try {
      await chmod(directory, 0o700);
    } catch {
      throw new Error("Unable to secure the send idempotency journal directory");
    }
  }
}

async function inspectJournalFile(filePath: string): Promise<"present" | "missing"> {
  let metadata;
  try {
    metadata = await lstat(filePath);
  } catch (error) {
    if (errorCode(error) === "ENOENT") {
      return "missing";
    }
    throw new Error("Unable to inspect the send idempotency journal");
  }
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1) {
    throw new Error("Send idempotency journal path is unsafe");
  }
  if (typeof process.getuid === "function" && metadata.uid !== process.getuid()) {
    throw new Error("Send idempotency journal has an unexpected owner");
  }
  if (process.platform !== "win32" && (metadata.mode & 0o077) !== 0) {
    throw new Error("Send idempotency journal permissions are unsafe");
  }
  if (metadata.size > MAX_JOURNAL_BYTES) {
    throw new Error("Send idempotency journal is too large");
  }
  return "present";
}

async function loadJournal(
  filePath: string,
  maxEntries: number,
): Promise<PersistentSendJournalFile> {
  if ((await inspectJournalFile(filePath)) === "missing") {
    return { version: JOURNAL_VERSION, entries: [] };
  }
  let raw: string;
  try {
    raw = await readFile(filePath, "utf8");
  } catch {
    throw new Error("Unable to read the send idempotency journal");
  }
  return parseJournal(raw, maxEntries);
}

async function saveJournal(
  filePath: string,
  journal: PersistentSendJournalFile,
): Promise<void> {
  const directory = dirname(filePath);
  await ensurePrivateDirectory(directory);
  await inspectJournalFile(filePath);
  const temporaryPath = join(directory, `.${JOURNAL_FILE_NAME}.${randomUUID()}.tmp`);
  let handle;
  try {
    handle = await open(temporaryPath, "wx", 0o600);
    await handle.writeFile(JSON.stringify(journal), "utf8");
    await handle.sync();
    await handle.close();
    handle = undefined;
    if (process.platform !== "win32") {
      await chmod(temporaryPath, 0o600);
    }
    await inspectJournalFile(filePath);
    await rename(temporaryPath, filePath);
  } catch (error) {
    throw error instanceof Error && error.message.includes("journal path is unsafe")
      ? error
      : new Error("Unable to save the send idempotency journal");
  } finally {
    await handle?.close().catch(() => undefined);
    await unlink(temporaryPath).catch(() => undefined);
  }
}

/**
 * Durable, privacy-minimal journal for message-send idempotency. Pending entries
 * are deliberately treated as uncertain after any reload or competing process.
 */
export class PersistentSendJournal {
  private readonly filePath: string;
  private readonly now: () => number;
  private readonly ttlMs: number;
  private readonly maxEntries: number;

  constructor(options: PersistentSendJournalOptions = {}) {
    this.filePath = resolve(options.filePath ?? defaultPersistentSendJournalPath());
    this.now = options.now ?? Date.now;
    this.ttlMs = options.ttlMs ?? DEFAULT_TTL_MS;
    this.maxEntries = options.maxEntries ?? DEFAULT_MAX_ENTRIES;
    if (!Number.isSafeInteger(this.ttlMs) || this.ttlMs <= 0) {
      throw new TypeError("ttlMs must be a positive safe integer");
    }
    if (!Number.isSafeInteger(this.maxEntries) || this.maxEntries <= 0 || this.maxEntries > 1_000) {
      throw new TypeError("maxEntries must be an integer between 1 and 1000");
    }
  }

  async begin(
    idempotencyKey: string,
    fingerprint: string,
  ): Promise<BeginSendResult> {
    validateIdempotencyKey(idempotencyKey);
    validateFingerprint(fingerprint);
    const normalizedFingerprint = fingerprint.toLowerCase();
    return this.withJournal(async (journal, now) => {
      const existing = journal.entries.find(
        (entry) => entry.idempotencyKey === idempotencyKey,
      );
      if (existing) {
        if (existing.fingerprint !== normalizedFingerprint) {
          return { result: "mismatch" as const, changed: false };
        }
        return {
          result:
            existing.state === "acknowledged"
              ? ("acknowledged" as const)
              : existing.state === "retired"
                ? ("retired" as const)
                : ("uncertain" as const),
          changed: false,
        };
      }
      if (journal.entries.length >= this.maxEntries) {
        throw new Error("Send idempotency journal is full");
      }
      journal.entries.push({
        idempotencyKey,
        fingerprint: normalizedFingerprint,
        state: "pending",
        timestamp: now,
      });
      return { result: "new" as const, changed: true };
    });
  }

  async acknowledge(
    idempotencyKey: string,
    fingerprint: string,
    insertedAt?: string,
  ): Promise<void> {
    validateInsertedAt(insertedAt);
    await this.transition(idempotencyKey, fingerprint, (entry, now) => {
      if (entry.state === "acknowledged") {
        return false;
      }
      if (entry.state !== "pending") {
        throw new Error("Only a pending send can be acknowledged");
      }
      entry.state = "acknowledged";
      entry.timestamp = now;
      if (insertedAt !== undefined) {
        entry.insertedAt = insertedAt;
      }
      return true;
    });
  }

  async markUnknown(idempotencyKey: string, fingerprint: string): Promise<void> {
    await this.transition(idempotencyKey, fingerprint, (entry, now) => {
      if (entry.state !== "pending") {
        return false;
      }
      entry.state = "unknown";
      entry.timestamp = now;
      delete entry.insertedAt;
      return true;
    });
  }

  async clearKnownFailure(
    idempotencyKey: string,
    fingerprint: string,
  ): Promise<void> {
    validateIdempotencyKey(idempotencyKey);
    validateFingerprint(fingerprint);
    await this.withJournal(async (journal) => {
      const index = journal.entries.findIndex(
        (entry) => entry.idempotencyKey === idempotencyKey,
      );
      if (index === -1) {
        return { result: undefined, changed: false };
      }
      const entry = journal.entries[index]!;
      this.assertFingerprint(entry, fingerprint);
      if (entry.state !== "pending") {
        throw new Error("Only a pending send with a known failure can be cleared");
      }
      journal.entries.splice(index, 1);
      return { result: undefined, changed: true };
    });
  }

  async remove(): Promise<void> {
    await withCtsRefreshLock(
      JOURNAL_LOCK_SCOPE,
      AbortSignal.timeout(60_000),
      async () => {
        await ensurePrivateDirectory(dirname(this.filePath));
        const state = await inspectJournalFile(this.filePath);
        if (state === "missing") {
          return;
        }
        try {
          await unlink(this.filePath);
        } catch {
          throw new Error("Unable to remove the send idempotency journal");
        }
      },
    );
  }

  async reconcile(
    idempotencyKey: string,
    outcome: ReconcileSendOutcome,
  ): Promise<void> {
    validateIdempotencyKey(idempotencyKey);
    if (outcome !== "delivered" && outcome !== "not_delivered") {
      throw new TypeError("reconciliation outcome is invalid");
    }
    await this.withJournal(async (journal, now) => {
      const index = journal.entries.findIndex(
        (entry) => entry.idempotencyKey === idempotencyKey,
      );
      if (index === -1) {
        throw new Error("Send idempotency journal entry is missing");
      }
      const entry = journal.entries[index]!;
      if (entry.state === "acknowledged") {
        if (outcome === "delivered") {
          return { result: undefined, changed: false };
        }
        throw new Error("An acknowledged send cannot be marked not delivered");
      }
      if (outcome === "delivered") {
        entry.state = "acknowledged";
        entry.timestamp = now;
      } else {
        if (entry.state === "retired") {
          return { result: undefined, changed: false };
        }
        entry.state = "retired";
        entry.timestamp = now;
        delete entry.insertedAt;
      }
      return { result: undefined, changed: true };
    });
  }

  private async transition(
    idempotencyKey: string,
    fingerprint: string,
    update: (entry: PersistentSendEntry, now: number) => boolean,
  ): Promise<void> {
    validateIdempotencyKey(idempotencyKey);
    validateFingerprint(fingerprint);
    await this.withJournal(async (journal, now) => {
      const entry = journal.entries.find(
        (candidate) => candidate.idempotencyKey === idempotencyKey,
      );
      if (!entry) {
        throw new Error("Send idempotency journal entry is missing");
      }
      this.assertFingerprint(entry, fingerprint);
      return { result: undefined, changed: update(entry, now) };
    });
  }

  private assertFingerprint(entry: PersistentSendEntry, fingerprint: string): void {
    if (entry.fingerprint !== fingerprint.toLowerCase()) {
      throw new Error("Idempotency key was already used for different message content");
    }
  }

  private async withJournal<T>(
    operation: (
      journal: PersistentSendJournalFile,
      now: number,
    ) => Promise<{ result: T; changed: boolean }>,
  ): Promise<T> {
    return withCtsRefreshLock(
      JOURNAL_LOCK_SCOPE,
      AbortSignal.timeout(60_000),
      async () => {
        const directory = dirname(this.filePath);
        await ensurePrivateDirectory(directory);
        const journal = await loadJournal(this.filePath, this.maxEntries);
        const now = this.now();
        if (!Number.isSafeInteger(now) || now < 0) {
          throw new Error("Journal clock returned an invalid timestamp");
        }
        const retained = journal.entries.filter(
          (entry) =>
            entry.state === "pending" ||
            entry.state === "unknown" ||
            now - entry.timestamp < this.ttlMs,
        );
        const pruned = retained.length !== journal.entries.length;
        journal.entries = retained;
        const { result, changed } = await operation(journal, now);
        if (pruned || changed) {
          await saveJournal(this.filePath, journal);
        }
        return result;
      },
    );
  }
}
