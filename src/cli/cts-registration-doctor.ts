import { diagnoseCtsRegistration } from "../auth/cts-registration-diagnostics.js";
import { NativeCredentialSessionStore } from "../auth/native-credential-session-store.js";

function status(value: number | null): string {
  return value === null ? "нет соединения" : `HTTP ${value}`;
}

async function main(): Promise<void> {
  const session = await new NativeCredentialSessionStore().load();
  const result = await diagnoseCtsRegistration(session, {
    signal: AbortSignal.timeout(30_000),
  });
  process.stdout.write(`CTS health: ${status(result.health.status)}\n`);
  process.stdout.write(
    `Регистрация обычного устройства: ${status(result.registration.status)}\n`,
  );
  if (result.registration.requestId) {
    process.stdout.write(`Request ID для администратора: ${result.registration.requestId}\n`);
  }
  if (result.conclusion === "available") {
    process.stdout.write(
      `Доступные штатные способы: ${result.registerMethods.join(", ")}\n`,
    );
    return;
  }
  if (result.conclusion === "registration-discovery-unavailable") {
    process.stdout.write(
      "Диагноз: CTS доступен, но справочный endpoint выбора способов входа вернул ошибку. Это само по себе не доказывает отказ QR-регистрации.\n",
    );
  } else if (result.conclusion === "cts-unreachable") {
    process.stdout.write("Диагноз: CTS недоступен по сети.\n");
  } else {
    process.stdout.write(
      "Диагноз: CTS вернул неожиданный ответ; нужна проверка серверных журналов.\n",
    );
  }
  process.exitCode = 2;
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : "Неизвестная ошибка";
  process.stderr.write(`Диагностика CTS не завершена: ${message}\n`);
  process.exitCode = 1;
});
