import { createHash, randomUUID } from "node:crypto";
import { fork, type ChildProcess } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";

import { afterEach, describe, expect, it } from "vitest";

type WorkerMessage = Record<string, unknown> & { event: string };

const WORKER_PATH = fileURLToPath(
  new URL("./fixtures/cross-process-state-worker.ts", import.meta.url),
);

const children = new Set<ChildProcess>();

interface WorkerHandle {
  child: ChildProcess;
  messages: WorkerMessage[];
  waitFor(event: string): Promise<WorkerMessage>;
  waitForExit(): Promise<number | null>;
}

function startWorker(): WorkerHandle {
  const child = fork(WORKER_PATH, [], {
    execArgv: ["--import", "tsx"],
    stdio: ["ignore", "ignore", "pipe", "ipc"],
  });
  children.add(child);
  let stderr = "";
  child.stderr?.setEncoding("utf8");
  child.stderr?.on("data", (chunk: string) => {
    stderr += chunk;
  });
  const messages: WorkerMessage[] = [];
  const waiters = new Set<{
    event: string;
    resolve: (message: WorkerMessage) => void;
    reject: (error: Error) => void;
    timeout: ReturnType<typeof setTimeout>;
  }>();
  child.on("message", (message: unknown) => {
    if (
      !message ||
      typeof message !== "object" ||
      !("event" in message) ||
      typeof message.event !== "string"
    ) {
      return;
    }
    const typed = message as WorkerMessage;
    messages.push(typed);
    for (const waiter of waiters) {
      if (waiter.event === typed.event) {
        clearTimeout(waiter.timeout);
        waiters.delete(waiter);
        waiter.resolve(typed);
      }
    }
  });
  const exited = new Promise<number | null>((resolve) => {
    child.once("exit", (code) => {
      children.delete(child);
      for (const waiter of waiters) {
        clearTimeout(waiter.timeout);
        waiter.reject(
          new Error(`Worker exited before ${waiter.event}: ${stderr.trim()}`),
        );
      }
      waiters.clear();
      resolve(code);
    });
  });
  return {
    child,
    messages,
    waitFor(event: string): Promise<WorkerMessage> {
      const existing = messages.find((message) => message.event === event);
      if (existing) return Promise.resolve(existing);
      return new Promise((resolve, reject) => {
        const waiter = {
          event,
          resolve,
          reject,
          timeout: setTimeout(() => {
            waiters.delete(waiter);
            reject(new Error(`Timed out waiting for worker ${event}: ${stderr.trim()}`));
          }, 10_000),
        };
        waiters.add(waiter);
      });
    },
    waitForExit: () => exited,
  };
}

async function readyWorker(): Promise<WorkerHandle> {
  const worker = startWorker();
  await worker.waitFor("ready");
  return worker;
}

async function runWorker(command: Record<string, unknown>): Promise<WorkerMessage> {
  const worker = await readyWorker();
  worker.child.send(command);
  const result = await Promise.race([
    worker.waitFor("result"),
    worker.waitFor("failed"),
  ]);
  const exitCode = await worker.waitForExit();
  if (result.event === "failed") {
    throw new Error(`Worker failed: ${String(result.name)}: ${String(result.message)}`);
  }
  expect(exitCode).toBe(0);
  return result;
}

function fingerprint(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

afterEach(async () => {
  for (const child of children) {
    child.kill();
  }
  await Promise.allSettled(
    [...children].map(
      (child) => new Promise<void>((resolve) => child.once("exit", () => resolve())),
    ),
  );
  children.clear();
});

describe("cross-process state coordination", () => {
  it("serializes a CTS refresh lock between separate Node processes", async () => {
    const registrationId = `synthetic-${randomUUID()}`;
    const first = await readyWorker();
    first.child.send({ action: "hold-lock", registrationId });
    await first.waitFor("entered");

    const second = await readyWorker();
    second.child.send({ action: "acquire-lock", registrationId });
    await delay(250);
    expect(second.messages.some(({ event }) => event === "entered")).toBe(false);

    first.child.send({ action: "release" });
    await first.waitFor("done");
    await second.waitFor("entered");
    await second.waitFor("done");
    expect(await Promise.all([first.waitForExit(), second.waitForExit()]))
      .toEqual([0, 0]);
  });

  it("cancels a cross-process CTS lock waiter without entering it", async () => {
    const registrationId = `synthetic-${randomUUID()}`;
    const first = await readyWorker();
    first.child.send({ action: "hold-lock", registrationId });
    await first.waitFor("entered");

    const second = await readyWorker();
    second.child.send({
      action: "acquire-lock",
      registrationId,
      abortAfterMs: 150,
    });
    const failure = await second.waitFor("failed");
    expect(second.messages.some(({ event }) => event === "entered")).toBe(false);
    expect(String(failure.name)).toMatch(/AbortError|TimeoutError/);
    expect(await second.waitForExit()).toBe(1);

    first.child.send({ action: "release" });
    await first.waitFor("done");
    expect(await first.waitForExit()).toBe(0);
  });

  it("preserves journal idempotency across separate process lifetimes", async () => {
    const directory = await mkdtemp(join(tmpdir(), "express-journal-process-test-"));
    const filePath = join(directory, "state", "send-idempotency.json");
    const pendingKey = "00000000-0000-4000-8000-000000000101";
    const acknowledgedKey = "00000000-0000-4000-8000-000000000102";
    try {
      await expect(runWorker({
        action: "journal-begin",
        filePath,
        idempotencyKey: pendingKey,
        fingerprint: fingerprint("pending after process exit"),
      })).resolves.toMatchObject({ result: "new" });
      await expect(runWorker({
        action: "journal-begin",
        filePath,
        idempotencyKey: pendingKey,
        fingerprint: fingerprint("pending after process exit"),
      })).resolves.toMatchObject({ result: "uncertain" });

      await expect(runWorker({
        action: "journal-begin",
        filePath,
        idempotencyKey: acknowledgedKey,
        fingerprint: fingerprint("acknowledged after process exit"),
        acknowledge: true,
      })).resolves.toMatchObject({ result: "new" });
      await expect(runWorker({
        action: "journal-begin",
        filePath,
        idempotencyKey: acknowledgedKey,
        fingerprint: fingerprint("acknowledged after process exit"),
      })).resolves.toMatchObject({ result: "acknowledged" });
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("does not lose journal records written by concurrent Node processes", async () => {
    const directory = await mkdtemp(join(tmpdir(), "express-journal-race-test-"));
    const filePath = join(directory, "state", "send-idempotency.json");
    const workers = await Promise.all(
      Array.from({ length: 5 }, () => readyWorker()),
    );
    const startAt = Date.now() + 300;
    try {
      workers.forEach((worker, index) => {
        worker.child.send({
          action: "journal-begin",
          filePath,
          idempotencyKey: `00000000-0000-4000-8000-${String(index + 201).padStart(12, "0")}`,
          fingerprint: fingerprint(`concurrent process ${index}`),
          startAt,
        });
      });
      const results = await Promise.all(workers.map((worker) => worker.waitFor("result")));
      expect(results.map(({ result }) => result)).toEqual([
        "new",
        "new",
        "new",
        "new",
        "new",
      ]);
      expect(await Promise.all(workers.map((worker) => worker.waitForExit())))
        .toEqual([0, 0, 0, 0, 0]);

      const stored = JSON.parse(await readFile(filePath, "utf8")) as {
        entries: Array<{ idempotencyKey: string }>;
      };
      expect(stored.entries).toHaveLength(5);
      expect(new Set(stored.entries.map(({ idempotencyKey }) => idempotencyKey)).size)
        .toBe(5);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("allows only one concurrent process to claim an idempotency key", async () => {
    const directory = await mkdtemp(join(tmpdir(), "express-journal-claim-test-"));
    const filePath = join(directory, "state", "send-idempotency.json");
    const idempotencyKey = "00000000-0000-4000-8000-000000000301";
    const digest = fingerprint("one cross-process send claim");
    const workers = await Promise.all(
      Array.from({ length: 4 }, () => readyWorker()),
    );
    const startAt = Date.now() + 300;
    try {
      for (const worker of workers) {
        worker.child.send({
          action: "journal-begin",
          filePath,
          idempotencyKey,
          fingerprint: digest,
          startAt,
        });
      }
      const results = await Promise.all(workers.map((worker) => worker.waitFor("result")));
      expect(results.map(({ result }) => result).sort()).toEqual([
        "new",
        "uncertain",
        "uncertain",
        "uncertain",
      ]);
      expect(await Promise.all(workers.map((worker) => worker.waitForExit())))
        .toEqual([0, 0, 0, 0]);

      const stored = JSON.parse(await readFile(filePath, "utf8")) as {
        entries: Array<{ idempotencyKey: string }>;
      };
      expect(stored.entries).toEqual([expect.objectContaining({ idempotencyKey })]);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});
