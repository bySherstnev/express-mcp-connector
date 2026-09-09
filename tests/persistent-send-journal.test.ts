import { createHash } from "node:crypto";
import {
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { PersistentSendJournal } from "../src/mcp/persistent-send-journal.js";

function fingerprint(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

describe("PersistentSendJournal", () => {
  let temporaryDirectory: string;
  let filePath: string;
  let now: number;

  beforeEach(async () => {
    temporaryDirectory = await mkdtemp(join(tmpdir(), "express-send-journal-test-"));
    filePath = join(temporaryDirectory, "state", "send-idempotency.json");
    now = 1_800_000_000_000;
  });

  afterEach(async () => {
    await rm(temporaryDirectory, { recursive: true, force: true });
  });

  function journal(options: { ttlMs?: number; maxEntries?: number } = {}) {
    return new PersistentSendJournal({
      filePath,
      now: () => now,
      ...options,
    });
  }

  it("persists only privacy-minimal pending metadata in a private atomic file", async () => {
    const key = "00000000-0000-4000-8000-000000000001";
    const digest = fingerprint("corporate:chat-id:message body");

    await expect(journal().begin(key, digest)).resolves.toBe("new");

    const stored = JSON.parse(await readFile(filePath, "utf8")) as unknown;
    expect(stored).toEqual({
      version: 1,
      entries: [{
        idempotencyKey: key,
        fingerprint: digest,
        state: "pending",
        timestamp: now,
      }],
    });
    expect(JSON.stringify(stored)).not.toContain("message body");
    expect(await readdir(join(temporaryDirectory, "state"))).toEqual([
      "send-idempotency.json",
    ]);
    if (process.platform !== "win32") {
      expect((await lstat(dirname(filePath))).mode & 0o077).toBe(0);
      expect((await lstat(filePath)).mode & 0o077).toBe(0);
    }
  });

  it("treats a pending entry as uncertain after reload", async () => {
    const key = "00000000-0000-4000-8000-000000000002";
    const digest = fingerprint("pending");
    await journal().begin(key, digest);

    await expect(journal().begin(key, digest)).resolves.toBe("uncertain");
  });

  it("persists acknowledged and unknown outcomes across instances", async () => {
    const acknowledgedKey = "00000000-0000-4000-8000-000000000003";
    const unknownKey = "00000000-0000-4000-8000-000000000004";
    const acknowledgedFingerprint = fingerprint("acknowledged");
    const unknownFingerprint = fingerprint("unknown");
    const first = journal();
    await first.begin(acknowledgedKey, acknowledgedFingerprint);
    await first.acknowledge(
      acknowledgedKey,
      acknowledgedFingerprint,
      "2027-01-15T08:00:00.000Z",
    );
    await first.begin(unknownKey, unknownFingerprint);
    await first.markUnknown(unknownKey, unknownFingerprint);

    const reloaded = journal();
    await expect(reloaded.begin(acknowledgedKey, acknowledgedFingerprint))
      .resolves.toBe("acknowledged");
    await expect(reloaded.begin(unknownKey, unknownFingerprint))
      .resolves.toBe("uncertain");
    expect(JSON.parse(await readFile(filePath, "utf8"))).toEqual({
      version: 1,
      entries: [
        expect.objectContaining({
          idempotencyKey: acknowledgedKey,
          state: "acknowledged",
          insertedAt: "2027-01-15T08:00:00.000Z",
        }),
        expect.objectContaining({
          idempotencyKey: unknownKey,
          state: "unknown",
        }),
      ],
    });
  });

  it("reports fingerprint mismatches without changing the stored entry", async () => {
    const key = "00000000-0000-4000-8000-000000000005";
    const original = fingerprint("original");
    const different = fingerprint("different");
    const instance = journal();
    await instance.begin(key, original);

    await expect(instance.begin(key, different)).resolves.toBe("mismatch");
    await expect(instance.acknowledge(key, different)).rejects.toThrow(
      /different message content/i,
    );
    await expect(journal().begin(key, original)).resolves.toBe("uncertain");
  });

  it("treats uppercase and lowercase SHA-256 fingerprints as equivalent", async () => {
    const key = "00000000-0000-4000-8000-000000000013";
    const digest = fingerprint("case-insensitive hex");
    const instance = journal();

    await expect(instance.begin(key, digest.toUpperCase())).resolves.toBe("new");
    await expect(instance.begin(key, digest)).resolves.toBe("uncertain");
    await expect(instance.acknowledge(key, digest.toUpperCase())).resolves.toBeUndefined();
    await expect(journal().begin(key, digest)).resolves.toBe("acknowledged");
  });

  it("clears only a matching pending send after a known failure", async () => {
    const key = "00000000-0000-4000-8000-000000000006";
    const digest = fingerprint("known failure");
    const instance = journal();
    await instance.begin(key, digest);
    await instance.clearKnownFailure(key, digest);

    await expect(instance.begin(key, digest)).resolves.toBe("new");
    await instance.acknowledge(key, digest);
    await expect(instance.clearKnownFailure(key, digest)).rejects.toThrow(
      /only a pending send/i,
    );
  });

  it("prunes entries at the 24-hour TTL and enforces its capacity", async () => {
    const firstKey = "00000000-0000-4000-8000-000000000007";
    const secondKey = "00000000-0000-4000-8000-000000000008";
    const thirdKey = "00000000-0000-4000-8000-000000000009";
    const instance = journal({ maxEntries: 2 });
    await instance.begin(firstKey, fingerprint("first"));
    await instance.acknowledge(firstKey, fingerprint("first"));
    await instance.begin(secondKey, fingerprint("second"));
    await instance.acknowledge(secondKey, fingerprint("second"));
    await expect(instance.begin(thirdKey, fingerprint("third"))).rejects.toThrow(
      /journal is full/i,
    );

    now += 24 * 60 * 60 * 1_000;
    await expect(instance.begin(thirdKey, fingerprint("third"))).resolves.toBe("new");
    const stored = JSON.parse(await readFile(filePath, "utf8")) as {
      entries: Array<{ idempotencyKey: string }>;
    };
    expect(stored.entries.map(({ idempotencyKey }) => idempotencyKey)).toEqual([
      thirdKey,
    ]);
  });

  it("retains unresolved outcomes beyond the acknowledgement TTL", async () => {
    const key = "00000000-0000-4000-8000-000000000014";
    const digest = fingerprint("unresolved forever");
    const instance = journal();
    await instance.begin(key, digest);
    await instance.markUnknown(key, digest);

    now += 30 * 24 * 60 * 60 * 1_000;

    await expect(journal().begin(key, digest)).resolves.toBe("uncertain");
  });

  it("removes the durable journal during local logout", async () => {
    const instance = journal();
    await instance.begin(
      "00000000-0000-4000-8000-000000000015",
      fingerprint("logout"),
    );

    await instance.remove();

    await expect(readFile(filePath, "utf8")).rejects.toMatchObject({
      code: "ENOENT",
    });
    await expect(instance.remove()).resolves.toBeUndefined();
  });

  it("resolves an uncertain outcome explicitly without permitting a silent retry", async () => {
    const deliveredKey = "00000000-0000-4000-8000-000000000016";
    const notDeliveredKey = "00000000-0000-4000-8000-000000000017";
    const deliveredDigest = fingerprint("reconciled delivered");
    const notDeliveredDigest = fingerprint("reconciled not delivered");
    const instance = journal();
    await instance.begin(deliveredKey, deliveredDigest);
    await instance.markUnknown(deliveredKey, deliveredDigest);
    await instance.begin(notDeliveredKey, notDeliveredDigest);
    await instance.markUnknown(notDeliveredKey, notDeliveredDigest);

    await instance.reconcile(deliveredKey, "delivered");
    await instance.reconcile(notDeliveredKey, "not_delivered");

    await expect(instance.begin(deliveredKey, deliveredDigest))
      .resolves.toBe("acknowledged");
    await expect(instance.begin(notDeliveredKey, notDeliveredDigest))
      .resolves.toBe("retired");
    await expect(instance.reconcile(deliveredKey, "not_delivered"))
      .rejects.toThrow(/acknowledged.*cannot be marked not delivered/i);

    now += 24 * 60 * 60 * 1_000;
    await expect(instance.begin(notDeliveredKey, notDeliveredDigest))
      .resolves.toBe("new");
  });

  it("serializes concurrent instances without losing either pending record", async () => {
    const firstKey = "00000000-0000-4000-8000-000000000010";
    const secondKey = "00000000-0000-4000-8000-000000000011";

    await expect(Promise.all([
      journal().begin(firstKey, fingerprint("first concurrent")),
      journal().begin(secondKey, fingerprint("second concurrent")),
    ])).resolves.toEqual(["new", "new"]);

    const stored = JSON.parse(await readFile(filePath, "utf8")) as {
      entries: Array<{ idempotencyKey: string }>;
    };
    expect(new Set(stored.entries.map(({ idempotencyKey }) => idempotencyKey)))
      .toEqual(new Set([firstKey, secondKey]));
  });

  it.skipIf(process.platform === "win32")(
    "rejects a symlink journal without touching its target",
    async () => {
      const stateDirectory = dirname(filePath);
      const target = join(temporaryDirectory, "do-not-touch.json");
      await mkdir(stateDirectory, { recursive: true, mode: 0o700 });
      await writeFile(target, "protected", { mode: 0o600 });
      await symlink(target, filePath);

      await expect(
        journal().begin(
          "00000000-0000-4000-8000-000000000012",
          fingerprint("symlink"),
        ),
      ).rejects.toThrow(/path is unsafe/i);
      await expect(readFile(target, "utf8")).resolves.toBe("protected");
    },
  );
});
