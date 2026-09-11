import { chmod, mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import QRCode from "qrcode";

import { APPLICATION_STORAGE_ID } from "../application-identity.js";
import { createDesktopDeviceMetadata } from "../auth/desktop-device-metadata.js";
import { NativeCredentialSessionStore } from "../auth/native-credential-session-store.js";
import { completeQrRegistration } from "../auth/standalone-qr-client.js";
import {
  ensureRequestIdentity,
  prepareRtsRequestIdentity,
} from "../auth/rts-session-bootstrap.js";
import {
  createQrRegistrationState,
  serializeQrPayload,
} from "../auth/standalone-qr-registration.js";
import { withConnectorLifecycleLock } from "../mcp/connector-lifecycle-lock.js";
import { removeTemporaryQrDirectory } from "./temporary-qr-cleanup.js";

function readRtsHost(argv: readonly string[]): string {
  const index = argv.indexOf("--rts-host");
  if (index === -1) {
    return "ru.public.express";
  }
  const value = argv[index + 1];
  if (!value) {
    throw new Error("После --rts-host необходимо указать домен");
  }
  return value;
}

async function main(): Promise<void> {
  const rtsHost = readRtsHost(process.argv.slice(2));
  let qrDirectory: string | undefined;
  try {
    qrDirectory = await mkdtemp(
      join(tmpdir(), `${APPLICATION_STORAGE_ID}-login-`),
    );
    if (process.platform !== "win32") {
      await chmod(qrDirectory, 0o700);
    }
    const state = await createQrRegistrationState();
    const qrPayload = serializeQrPayload(state);
    const qrPath = join(qrDirectory, "pairing.png");
    await QRCode.toFile(qrPath, qrPayload, {
      width: 640,
      margin: 4,
      errorCorrectionLevel: "M",
    });
    if (process.platform !== "win32") {
      await chmod(qrPath, 0o600);
    }

    process.stdout.write(
      `QR сохранён: ${qrPath}\nОткройте eXpress на телефоне, выберите добавление устройства и отсканируйте QR.\n`,
    );
    process.stdout.write("Ожидаю подтверждение устройства…\n");

    const store = new NativeCredentialSessionStore();
    const lifecycleSignal = AbortSignal.timeout(10 * 60 * 1_000);
    let session!: Awaited<ReturnType<typeof completeQrRegistration>>;
    await withConnectorLifecycleLock(lifecycleSignal, async () => {
      const pairingSignal = AbortSignal.any([
        lifecycleSignal,
        AbortSignal.timeout(5 * 60 * 1_000),
      ]);
      session = await completeQrRegistration({
        initialRtsHost: rtsHost,
        state,
        device: createDesktopDeviceMetadata(),
        signal: pairingSignal,
      });
      // Pairing may finish at the edge of its five-minute deadline. Start a new
      // post-pairing budget so one-time tokens cannot expire before checkpoint.
      const postPairingSignal = AbortSignal.timeout(5 * 60 * 1_000);
      await store.withExclusiveAccess(postPairingSignal, async () => {
        // QR tokens and transferred E2E keys are one-time material. Persist
        // them before any repairable signing-key upload can fail.
        await store.save(session);
        session = await prepareRtsRequestIdentity(session);
        await store.save(session);
        const connections = session.cts?.active
          ? (["rts", "cts"] as const)
          : (["rts"] as const);
        for (const connection of connections) {
          session = await ensureRequestIdentity(
            session,
            [connection],
            fetch,
            postPairingSignal,
          );
          await store.save(session);
        }
      });
    });
    const corporateStatus = session.cts
      ? "подключён"
      : session.ctsPending
        ? "RTS подключён, CTS ожидает повторного подтверждения"
        : "не подключён";
    process.stdout.write(
      `Устройство подключено. Корпоративный профиль: ${corporateStatus}. Ключи отправки зарегистрированы.\n`,
    );
  } finally {
    if (qrDirectory) {
      await removeTemporaryQrDirectory(qrDirectory);
    }
  }
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : "Неизвестная ошибка";
  process.stderr.write(`Авторизация не завершена: ${message}\n`);
  process.exitCode = 1;
});
