import { createHash, randomUUID } from "node:crypto";
import { AsyncLocalStorage } from "node:async_hooks";

import keyring from "@napi-rs/keyring/keytar.js";

import { APPLICATION_STORAGE_ID } from "../application-identity.js";
import type { StandaloneExpressSession } from "./standalone-qr-client.js";
import { withCtsRefreshLock } from "./cts-refresh-lock.js";

const SERVICE = `${APPLICATION_STORAGE_ID} standalone`;
const LEGACY_ACCOUNT = "session.v1";
const MANIFEST_ACCOUNT = "session.v2";
const SESSION_LOCK_SCOPE = `${APPLICATION_STORAGE_ID} standalone session store`;
const sessionLockContext = new AsyncLocalStorage<boolean>();
// Windows Credential Manager stores passwords as UTF-16 and limits the
// credential blob to 2560 bytes. Base64 is ASCII, so 1200 characters occupy
// 2400 bytes and leave a small margin for backend-specific behavior.
const CREDENTIAL_CHUNK_CHARACTERS = 1_200;
const MAX_CHUNKS = 128;

interface SessionManifest {
  version: 2;
  generation: string;
  chunks: number;
  sha256: string;
  encoding: "base64";
}

export interface NativeCredentialClient {
  setPassword(service: string, account: string, password: string): Promise<void>;
  getPassword(service: string, account: string): Promise<string | null>;
  deletePassword(service: string, account: string): Promise<boolean>;
  findCredentials?(service: string): Promise<Array<{ account: string; password: string }>>;
}

function isChunkAccount(account: string): boolean {
  return /^session\.v2\.[0-9a-f-]{36}\.\d+$/i.test(account);
}

function isSession(value: unknown): value is StandaloneExpressSession {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const session = value as Partial<StandaloneExpressSession>;
  return (
    session.version === 1 &&
    typeof session.createdAt === "string" &&
    !!session.rts &&
    typeof session.rts.host === "string" &&
    typeof session.rts.authToken === "string" &&
    !!session.device &&
    typeof session.device.signingPrivateKey === "string" &&
    !!session.encryptionKeys &&
    typeof session.encryptionKeys === "object"
  );
}

function isManifest(value: unknown): value is SessionManifest {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const manifest = value as Partial<SessionManifest>;
  return (
    manifest.version === 2 &&
    typeof manifest.generation === "string" &&
    /^[0-9a-f-]{36}$/i.test(manifest.generation) &&
    Number.isInteger(manifest.chunks) &&
    (manifest.chunks ?? 0) > 0 &&
    (manifest.chunks ?? 0) <= MAX_CHUNKS &&
    typeof manifest.sha256 === "string" &&
    /^[0-9a-f]{64}$/i.test(manifest.sha256) &&
    manifest.encoding === "base64"
  );
}

function chunkAccount(generation: string, index: number): string {
  return `${MANIFEST_ACCOUNT}.${generation}.${index}`;
}

function parseManifest(raw: string | null): SessionManifest | null {
  if (!raw) return null;
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    throw new Error("Stored eXpress session manifest is invalid");
  }
  if (!isManifest(value)) {
    throw new Error("Stored eXpress session manifest is invalid");
  }
  return value;
}

function parseSession(raw: string): StandaloneExpressSession {
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    throw new Error("Stored eXpress session is invalid");
  }
  if (!isSession(value)) {
    throw new Error("Stored eXpress session is invalid");
  }
  return value;
}

/**
 * Stores the complete device session in the credential service provided by
 * the operating system. The native backend maps this to macOS Keychain,
 * Windows Credential Manager, and Secret Service/libsecret on Linux.
 */
export class NativeCredentialSessionStore {
  constructor(private readonly credentials: NativeCredentialClient = keyring) {}

  async withExclusiveAccess<T>(
    signal: AbortSignal,
    operation: () => Promise<T>,
  ): Promise<T> {
    if (sessionLockContext.getStore() === true) {
      return operation();
    }
    return withCtsRefreshLock(SESSION_LOCK_SCOPE, signal, () =>
      sessionLockContext.run(true, operation),
    );
  }

  async save(session: StandaloneExpressSession): Promise<void> {
    if (sessionLockContext.getStore() !== true) {
      return this.withExclusiveAccess(AbortSignal.timeout(60_000), () =>
        this.save(session),
      );
    }
    const raw = JSON.stringify(session);
    const encoded = Buffer.from(raw, "utf8").toString("base64");
    const chunks: string[] = [];
    for (let offset = 0; offset < encoded.length; offset += CREDENTIAL_CHUNK_CHARACTERS) {
      chunks.push(encoded.slice(offset, offset + CREDENTIAL_CHUNK_CHARACTERS));
    }
    if (chunks.length === 0 || chunks.length > MAX_CHUNKS) {
      throw new Error("eXpress session is too large for the system credential store");
    }
    const generation = randomUUID();
    const manifest: SessionManifest = {
      version: 2,
      generation,
      chunks: chunks.length,
      sha256: createHash("sha256").update(raw, "utf8").digest("hex"),
      encoding: "base64",
    };
    let previousManifest: SessionManifest | null = null;
    try {
      previousManifest = parseManifest(
        await this.credentials.getPassword(SERVICE, MANIFEST_ACCOUNT),
      );
      for (const [index, chunk] of chunks.entries()) {
        await this.credentials.setPassword(
          SERVICE,
          chunkAccount(generation, index),
          chunk,
        );
      }
      // Publishing the manifest last makes a save atomic from a reader's point
      // of view: it either sees the old complete generation or the new one.
      await this.credentials.setPassword(
        SERVICE,
        MANIFEST_ACCOUNT,
        JSON.stringify(manifest),
      );
    } catch {
      await Promise.allSettled(
        chunks.map((_chunk, index) =>
          this.credentials.deletePassword(
            SERVICE,
            chunkAccount(generation, index),
          )),
      );
      throw new Error("Unable to save eXpress session in the system credential store");
    }

    // Cleanup is deliberately best-effort after the new generation is live.
    await this.credentials.deletePassword(SERVICE, LEGACY_ACCOUNT).catch(() => false);
    if (previousManifest && previousManifest.generation !== generation) {
      await Promise.allSettled(
        Array.from({ length: previousManifest.chunks }, (_unused, index) =>
          this.credentials.deletePassword(
            SERVICE,
            chunkAccount(previousManifest.generation, index),
          )),
      );
    }
    if (this.credentials.findCredentials) {
      try {
        const currentPrefix = `${MANIFEST_ACCOUNT}.${generation}.`;
        const credentials = await this.credentials.findCredentials(SERVICE);
        await Promise.allSettled(
          credentials
            .filter(
              ({ account }) =>
                isChunkAccount(account) && !account.startsWith(currentPrefix),
            )
            .map(({ account }) =>
              this.credentials.deletePassword(SERVICE, account),
            ),
        );
      } catch {
        // The newly published generation is still valid; orphan cleanup is
        // retried by the next save or an explicit logout.
      }
    }
  }

  async load(): Promise<StandaloneExpressSession> {
    let raw: string | null;
    try {
      const manifest = parseManifest(
        await this.credentials.getPassword(SERVICE, MANIFEST_ACCOUNT),
      );
      if (!manifest) {
        raw = await this.credentials.getPassword(SERVICE, LEGACY_ACCOUNT);
      } else {
        const chunks = await Promise.all(
          Array.from({ length: manifest.chunks }, (_unused, index) =>
            this.credentials.getPassword(
              SERVICE,
              chunkAccount(manifest.generation, index),
            )),
        );
        if (chunks.some((chunk) => chunk === null)) {
          throw new Error("Stored eXpress session is incomplete");
        }
        raw = Buffer.from(chunks.join(""), "base64").toString("utf8");
        const digest = createHash("sha256").update(raw, "utf8").digest("hex");
        if (digest !== manifest.sha256) {
          throw new Error("Stored eXpress session checksum does not match");
        }
      }
    } catch {
      throw new Error("Unable to access the system credential store");
    }
    if (!raw) {
      throw new Error("Stored eXpress session is missing");
    }
    return parseSession(raw);
  }

  async remove(): Promise<void> {
    if (sessionLockContext.getStore() !== true) {
      return this.withExclusiveAccess(AbortSignal.timeout(60_000), () =>
        this.remove(),
      );
    }
    let incomplete = false;
    const accounts = new Set([MANIFEST_ACCOUNT, LEGACY_ACCOUNT]);
    try {
      const manifest = parseManifest(
        await this.credentials.getPassword(SERVICE, MANIFEST_ACCOUNT),
      );
      if (manifest) {
        for (let index = 0; index < manifest.chunks; index += 1) {
          accounts.add(chunkAccount(manifest.generation, index));
        }
      }
    } catch {
      incomplete = true;
    }
    if (this.credentials.findCredentials) {
      try {
        const credentials = await this.credentials.findCredentials(SERVICE);
        for (const { account } of credentials) {
          if (isChunkAccount(account)) {
            accounts.add(account);
          }
        }
      } catch {
        incomplete = true;
      }
    }
    const deletions = await Promise.allSettled(
      [...accounts].map((account) =>
        this.credentials.deletePassword(SERVICE, account),
      ),
    );
    if (
      incomplete ||
      deletions.some((result) => result.status === "rejected")
    ) {
      throw new Error("Unable to remove eXpress session from the system credential store");
    }
  }
}
