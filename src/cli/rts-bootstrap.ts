import { NativeCredentialSessionStore } from "../auth/native-credential-session-store.js";
import {
  fetchRtsServerPublicKey,
  ensureRequestIdentity,
  prepareRtsRequestIdentity,
} from "../auth/rts-session-bootstrap.js";
import { withConnectorLifecycleLock } from "../mcp/connector-lifecycle-lock.js";

async function main(): Promise<void> {
  const store = new NativeCredentialSessionStore();
  const signal = AbortSignal.timeout(60_000);
  await withConnectorLifecycleLock(signal, () =>
    store.withExclusiveAccess(signal, async () => {
    let session = await store.load();
    session = await fetchRtsServerPublicKey(session, fetch, signal);
    await store.save(session);
    session = await prepareRtsRequestIdentity(session);
    await store.save(session);
    const connections = session.cts?.active
      ? (["rts", "cts"] as const)
      : (["rts"] as const);
    for (const connection of connections) {
      session = await ensureRequestIdentity(session, [connection], fetch, signal);
      await store.save(session);
    }
    }),
  );
  process.stdout.write(
    "Сессия проверена; signing-ключ зарегистрирован во всех активных контурах.\n",
  );
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : "Неизвестная ошибка";
  process.stderr.write(`RTS bootstrap не завершён: ${message}\n`);
  process.exitCode = 1;
});
