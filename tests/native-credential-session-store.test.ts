import { describe, expect, it, vi } from "vitest";

import {
  NativeCredentialSessionStore,
  type NativeCredentialClient,
} from "../src/auth/native-credential-session-store.js";
import type { StandaloneExpressSession } from "../src/auth/standalone-qr-client.js";

const SESSION: StandaloneExpressSession = {
  version: 1,
  createdAt: "2026-01-01T00:00:00.000Z",
  rts: {
    host: "synthetic.invalid",
    authToken: "SYNTHETIC_TOKEN",
    expiresAt: null,
    userHuid: "synthetic-user",
    serverId: "synthetic-server",
  },
  device: {
    udid: "synthetic-udid",
    registrationId: "synthetic-registration",
    signingKeyId: "synthetic-sign-key",
    signingAlgorithm: "ed25519",
    signingPublicKey: "SYNTHETIC_PUBLIC",
    signingPrivateKey: "SYNTHETIC_PRIVATE",
  },
  encryptionKeys: { synthetic: true },
};

describe("NativeCredentialSessionStore", () => {
  function memoryCredentials(
    initial: Record<string, string> = {},
    maximumPasswordBytes?: number,
  ) {
    const values = new Map(Object.entries(initial));
    const credentials: NativeCredentialClient = {
      setPassword: vi.fn(async (_service, account, password) => {
        if (
          maximumPasswordBytes !== undefined &&
          Buffer.byteLength(password, "utf16le") > maximumPasswordBytes
        ) {
          throw new Error("Credential blob exceeds the platform limit");
        }
        values.set(account, password);
      }),
      getPassword: vi.fn(async (_service, account) => values.get(account) ?? null),
      deletePassword: vi.fn(async (_service, account) => values.delete(account)),
      findCredentials: vi.fn(async () =>
        [...values].map(([account, password]) => ({ account, password })),
      ),
    };
    return { credentials, values };
  }

  it("chunks a large session below the Windows Credential Manager limit", async () => {
    const windowsCredentialBlobLimit = 2_560;
    const { credentials, values } = memoryCredentials(
      {},
      windowsCredentialBlobLimit,
    );
    const store = new NativeCredentialSessionStore(credentials);
    const largeSession: StandaloneExpressSession = {
      ...SESSION,
      encryptionKeys: { payload: "x".repeat(8_000) },
    };

    await store.save(largeSession);

    const chunks = [...values.entries()].filter(([account]) =>
      /^session\.v2\.[0-9a-f-]{36}\.\d+$/i.test(account),
    );
    expect(chunks.length).toBeGreaterThan(1);
    expect(
      chunks.every(
        ([, value]) =>
          Buffer.byteLength(value, "utf16le") <= windowsCredentialBlobLimit,
      ),
    ).toBe(true);
    expect(values.has("session.v2")).toBe(true);
    expect(values.has("session.v1")).toBe(false);
    await expect(store.load()).resolves.toEqual(largeSession);
  });

  it("loads a legacy macOS session without forcing a new QR login", async () => {
    const { credentials } = memoryCredentials({
      "session.v1": JSON.stringify(SESSION),
    });
    const store = new NativeCredentialSessionStore(credentials);

    await expect(store.load()).resolves.toEqual(SESSION);
  });

  it("removes the manifest, every chunk, and a possible legacy record", async () => {
    const { credentials, values } = memoryCredentials();
    const store = new NativeCredentialSessionStore(credentials);
    await store.save({
      ...SESSION,
      encryptionKeys: { payload: "x".repeat(8_000) },
    });
    values.set("session.v1", JSON.stringify(SESSION));
    values.set(
      "session.v2.00000000-0000-4000-8000-000000000000.0",
      "orphaned-secret-chunk",
    );

    await store.remove();

    expect(values.size).toBe(0);
  });

  it("serializes concurrent saves without deleting the active generation", async () => {
    const { credentials } = memoryCredentials();
    const store = new NativeCredentialSessionStore(credentials);
    const sessions = Array.from({ length: 6 }, (_unused, index) => ({
      ...SESSION,
      createdAt: `2026-01-01T00:00:0${index}.000Z`,
      encryptionKeys: { payload: String(index).repeat(6_000) },
    }));

    await Promise.all(sessions.map((session) => store.save(session)));
    const restored = await store.load();

    expect(sessions).toContainEqual(restored);
  });

  it("still enumerates and deletes chunks when the manifest is corrupt", async () => {
    const { credentials, values } = memoryCredentials({
      "session.v2": "not-json",
      "session.v1": JSON.stringify(SESSION),
      "session.v2.00000000-0000-4000-8000-000000000000.0":
        "orphaned-secret-chunk",
    });
    const store = new NativeCredentialSessionStore(credentials);

    await expect(store.remove()).rejects.toThrow(
      "Unable to remove eXpress session",
    );
    expect(values.size).toBe(0);
  });
});
