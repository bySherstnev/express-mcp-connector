import { confirmPendingCtsSession } from "../auth/cts-session-confirmation.js";
import { NativeCredentialSessionStore } from "../auth/native-credential-session-store.js";
import {
  ensureRequestIdentity,
  prepareRtsRequestIdentity,
} from "../auth/rts-session-bootstrap.js";
import { withConnectorLifecycleLock } from "../mcp/connector-lifecycle-lock.js";

async function main(): Promise<void> {
  const store = new NativeCredentialSessionStore();
  const signal = AbortSignal.timeout(30_000);
  const message = await withConnectorLifecycleLock(signal, () =>
    store.withExclusiveAccess(signal, async () => {
    const current = await store.load();
    if (!current.ctsPending) {
      return current.cts
        ? "CTS-сессия уже подключена.\n"
        : "В сохранённой сессии нет ожидающего CTS-подтверждения.\n";
    }
    let updated = await confirmPendingCtsSession(current, { signal });
    await store.save(updated);
    updated = await prepareRtsRequestIdentity(updated);
    await store.save(updated);
    updated = await ensureRequestIdentity(updated, ["cts"], fetch, signal);
    await store.save(updated);
    return "CTS-сессия подключена; ключ отправки зарегистрирован и сохранён.\n";
    }),
  );
  process.stdout.write(message);
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : "Неизвестная ошибка";
  process.stderr.write(`CTS bootstrap не завершён: ${message}\n`);
  process.exitCode = 1;
});
