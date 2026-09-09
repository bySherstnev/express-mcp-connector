import { setTimeout as delay } from "node:timers/promises";

import { withCtsRefreshLock } from "../../src/auth/cts-refresh-lock.js";
import { PersistentSendJournal } from "../../src/mcp/persistent-send-journal.js";

type WorkerCommand =
  | {
      action: "hold-lock";
      registrationId: string;
    }
  | {
      action: "acquire-lock";
      registrationId: string;
      abortAfterMs?: number;
    }
  | {
      action: "journal-begin";
      filePath: string;
      idempotencyKey: string;
      fingerprint: string;
      acknowledge?: boolean;
      startAt?: number;
    };

function send(message: Record<string, unknown>): Promise<void> {
  return new Promise((resolve, reject) => {
    if (!process.send) {
      reject(new Error("IPC channel is unavailable"));
      return;
    }
    process.send(message, (error) => error ? reject(error) : resolve());
  });
}

async function finish(message: Record<string, unknown>): Promise<void> {
  await send(message);
  process.disconnect();
}

function waitForRelease(): Promise<void> {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(
      () => reject(new Error("Timed out waiting for parent release")),
      15_000,
    );
    const onMessage = (message: unknown): void => {
      if (
        message &&
        typeof message === "object" &&
        "action" in message &&
        message.action === "release"
      ) {
        clearTimeout(timeout);
        process.off("message", onMessage);
        resolve();
      }
    };
    process.on("message", onMessage);
  });
}

async function run(command: WorkerCommand): Promise<void> {
  switch (command.action) {
    case "hold-lock":
      await withCtsRefreshLock(
        command.registrationId,
        AbortSignal.timeout(15_000),
        async () => {
          await send({ event: "entered" });
          await waitForRelease();
        },
      );
      await finish({ event: "done" });
      return;

    case "acquire-lock": {
      const signal = command.abortAfterMs === undefined
        ? AbortSignal.timeout(15_000)
        : AbortSignal.timeout(command.abortAfterMs);
      await withCtsRefreshLock(command.registrationId, signal, async () => {
        await send({ event: "entered" });
      });
      await finish({ event: "done" });
      return;
    }

    case "journal-begin": {
      if (command.startAt !== undefined) {
        await delay(Math.max(0, command.startAt - Date.now()));
      }
      const journal = new PersistentSendJournal({ filePath: command.filePath });
      const result = await journal.begin(
        command.idempotencyKey,
        command.fingerprint,
      );
      if (command.acknowledge && result === "new") {
        await journal.acknowledge(
          command.idempotencyKey,
          command.fingerprint,
          "2026-09-08T15:00:00.000Z",
        );
      }
      await finish({ event: "result", result });
      return;
    }
  }
}

process.once("message", (message) => {
  void run(message as WorkerCommand).catch(async (error: unknown) => {
    const value = error instanceof Error
      ? { name: error.name, message: error.message }
      : { name: "Error", message: "Unknown worker failure" };
    await finish({ event: "failed", ...value }).catch(() => undefined);
    process.exitCode = 1;
  });
});

await send({ event: "ready" });
