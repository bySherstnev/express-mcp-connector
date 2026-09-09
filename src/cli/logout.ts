import { NativeCredentialSessionStore } from "../auth/native-credential-session-store.js";
import { withConnectorLifecycleLock } from "../mcp/connector-lifecycle-lock.js";
import { PersistentSendJournal } from "../mcp/persistent-send-journal.js";

async function main(): Promise<void> {
  const signal = AbortSignal.timeout(60_000);
  await withConnectorLifecycleLock(signal, async () => {
    // Preserve idempotency protection if credential deletion fails. Once the
    // session is gone no new send can start, so the journal can be removed.
    await new NativeCredentialSessionStore().remove();
    await new PersistentSendJournal().remove();
  });
  process.stdout.write(
    "Локальная сессия, ключи и журнал отправок eXpress удалены. " +
      "Чтобы отозвать устройство на сервере, закройте его в списке открытых сессий eXpress.\n",
  );
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : "Неизвестная ошибка";
  process.stderr.write(`Не удалось удалить локальную сессию: ${message}\n`);
  process.exitCode = 1;
});
