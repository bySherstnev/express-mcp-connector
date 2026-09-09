import { requestCtsEmailCode } from "../auth/cts-email-auth.js";
import { NativeCredentialSessionStore } from "../auth/native-credential-session-store.js";
import { withConnectorLifecycleLock } from "../mcp/connector-lifecycle-lock.js";

function readEmail(argv: readonly string[], stored: unknown): string {
  const index = argv.indexOf("--email");
  const value = index === -1 ? stored : argv[index + 1];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error("Укажите корпоративную почту через --email");
  }
  return value;
}

async function main(): Promise<void> {
  const store = new NativeCredentialSessionStore();
  const signal = AbortSignal.timeout(30_000);
  await withConnectorLifecycleLock(signal, () =>
    store.withExclusiveAccess(signal, async () => {
    const session = await store.load();
    const email = readEmail(
      process.argv.slice(2),
      session.encryptionKeys.cts_login,
    );
    const updated = await requestCtsEmailCode(session, email, { signal });
    await store.save(updated);
    }),
  );
  process.stdout.write(
    "Код корпоративного входа запрошен и ожидается; адрес не выводится.\n",
  );
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : "Неизвестная ошибка";
  process.stderr.write(`CTS email-вход не начат: ${message}\n`);
  process.exitCode = 1;
});
