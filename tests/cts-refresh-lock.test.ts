import { createHash, randomUUID } from "node:crypto";
import { mkdir, readdir, rmdir, stat, utimes } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it, vi } from "vitest";

import { APPLICATION_STORAGE_ID } from "../src/application-identity.js";
import { withCtsRefreshLock } from "../src/auth/cts-refresh-lock.js";

const BASE_DIRECTORY = join(
  tmpdir(),
  `${APPLICATION_STORAGE_ID}-${typeof process.getuid === "function" ? process.getuid() : "user"}-cts-refresh-locks`,
);

function lockDirectory(registrationId: string): string {
  const digest = createHash("sha256")
    .update(registrationId, "utf8")
    .digest("hex");
  return join(BASE_DIRECTORY, `${digest}.lock`);
}

describe("cross-process CTS refresh lock", () => {
  it("serializes operations for the same registration without exposing its id", async () => {
    const registrationId = `sensitive-${randomUUID()}`;
    const entered: number[] = [];
    let active = 0;
    let maxActive = 0;
    let releaseFirst!: () => void;
    const firstGate = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });

    const first = withCtsRefreshLock(
      registrationId,
      new AbortController().signal,
      async () => {
        active += 1;
        maxActive = Math.max(maxActive, active);
        entered.push(1);
        await firstGate;
        active -= 1;
        return "first";
      },
    );
    await vi.waitFor(() => expect(entered).toEqual([1]));
    const second = withCtsRefreshLock(
      registrationId,
      new AbortController().signal,
      async () => {
        active += 1;
        maxActive = Math.max(maxActive, active);
        entered.push(2);
        active -= 1;
        return "second";
      },
    );

    await new Promise((resolve) => setTimeout(resolve, 80));
    expect(entered).toEqual([1]);
    expect((await readdir(BASE_DIRECTORY)).join("\n")).not.toContain(
      registrationId,
    );
    releaseFirst();

    await expect(first).resolves.toBe("first");
    await expect(second).resolves.toBe("second");
    expect(maxActive).toBe(1);
    await expect(stat(lockDirectory(registrationId))).rejects.toMatchObject({
      code: "ENOENT",
    });
  });

  it("stops waiting when the caller aborts", async () => {
    const registrationId = randomUUID();
    let releaseFirst!: () => void;
    const firstGate = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    let firstEntered = false;
    const first = withCtsRefreshLock(
      registrationId,
      new AbortController().signal,
      async () => {
        firstEntered = true;
        await firstGate;
      },
    );
    await vi.waitFor(() => expect(firstEntered).toBe(true));

    const controller = new AbortController();
    const secondOperation = vi.fn();
    const second = withCtsRefreshLock(
      registrationId,
      controller.signal,
      secondOperation,
    );
    controller.abort(new Error("synthetic deadline"));

    await expect(second).rejects.toThrow("synthetic deadline");
    expect(secondOperation).not.toHaveBeenCalled();
    releaseFirst();
    await first;
  });

  it("recovers an old incomplete lock and releases it after use", async () => {
    const registrationId = randomUUID();
    await mkdir(BASE_DIRECTORY, { recursive: true, mode: 0o700 });
    const staleDirectory = lockDirectory(registrationId);
    await mkdir(staleDirectory, { mode: 0o700 });
    const old = new Date(Date.now() - 3 * 60_000);
    await utimes(staleDirectory, old, old);

    const operation = vi.fn().mockResolvedValue("recovered");
    await expect(
      withCtsRefreshLock(
        registrationId,
        AbortSignal.timeout(2_000),
        operation,
      ),
    ).resolves.toBe("recovered");

    expect(operation).toHaveBeenCalledOnce();
    await expect(stat(staleDirectory)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("releases its exact lock when the operation throws", async () => {
    const registrationId = randomUUID();
    await expect(
      withCtsRefreshLock(
        registrationId,
        new AbortController().signal,
        async () => {
          throw new Error("synthetic refresh failure");
        },
      ),
    ).rejects.toThrow("synthetic refresh failure");

    await expect(stat(lockDirectory(registrationId))).rejects.toMatchObject({
      code: "ENOENT",
    });
    await expect(
      withCtsRefreshLock(
        registrationId,
        AbortSignal.timeout(2_000),
        async () => "next",
      ),
    ).resolves.toBe("next");
  });

  it("never recursively removes unexpected stale-lock contents", async () => {
    const registrationId = randomUUID();
    await mkdir(BASE_DIRECTORY, { recursive: true, mode: 0o700 });
    const staleDirectory = lockDirectory(registrationId);
    await mkdir(staleDirectory, { mode: 0o700 });
    await mkdir(join(staleDirectory, "unexpected"), { mode: 0o700 });
    const old = new Date(Date.now() - 3 * 60_000);
    await utimes(staleDirectory, old, old);

    await expect(
      withCtsRefreshLock(
        registrationId,
        AbortSignal.timeout(2_000),
        async () => "safe",
      ),
    ).resolves.toBe("safe");

    const leftovers = (await readdir(BASE_DIRECTORY)).filter((name) =>
      name.includes(".stale-"),
    );
    expect(leftovers.length).toBeGreaterThan(0);
    for (const name of leftovers) {
      const quarantine = join(BASE_DIRECTORY, name);
      try {
        await rmdir(join(quarantine, "unexpected"));
        await rmdir(quarantine);
      } catch {
        // A concurrent test may own a different quarantine entry.
      }
    }
  });
});
