import { confirmCtsEmailCode } from "../auth/cts-email-auth.js";
import { NativeCredentialSessionStore } from "../auth/native-credential-session-store.js";
import {
  ensureRequestIdentity,
  prepareRtsRequestIdentity,
} from "../auth/rts-session-bootstrap.js";
import { withConnectorLifecycleLock } from "../mcp/connector-lifecycle-lock.js";
import { readHiddenSixDigitCode } from "./hidden-code-input.js";

async function main(): Promise<void> {
  const store = new NativeCredentialSessionStore();
  const code = await readHiddenSixDigitCode(process.argv.slice(2));
  const signal = AbortSignal.timeout(30_000);
  await withConnectorLifecycleLock(signal, () =>
    store.withExclusiveAccess(signal, async () => {
    const session = await store.load();
    let updated = await confirmCtsEmailCode(session, code, { signal });
    await store.save(updated);
    updated = await prepareRtsRequestIdentity(updated);
    await store.save(updated);
    updated = await ensureRequestIdentity(updated, ["cts"], fetch, signal);
    await store.save(updated);
    }),
  );
  process.stdout.write("Корпоративная CTS-сессия и ключ отправки сохранены.\n");
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : "Неизвестная ошибка";
  process.stderr.write(`CTS email-вход не завершён: ${message}\n`);
  process.exitCode = 1;
});
