import { withConnectorLifecycleLock } from "../mcp/connector-lifecycle-lock.js";
import { PersistentSendJournal } from "../mcp/persistent-send-journal.js";

function parseArguments(argv: readonly string[]): {
  idempotencyKey: string;
  outcome: "delivered" | "not_delivered";
} {
  const [idempotencyKey, outcome, ...extra] = argv;
  if (
    extra.length > 0 ||
    typeof idempotencyKey !== "string" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(idempotencyKey) ||
    (outcome !== "delivered" && outcome !== "not_delivered")
  ) {
    throw new Error(
      "Использование: npm run send:reconcile -- <uuid> delivered|not_delivered",
    );
  }
  return { idempotencyKey, outcome };
}

async function main(): Promise<void> {
  const { idempotencyKey, outcome } = parseArguments(process.argv.slice(2));
  const signal = AbortSignal.timeout(60_000);
  await withConnectorLifecycleLock(signal, () =>
    new PersistentSendJournal().reconcile(idempotencyKey, outcome),
  );
  process.stdout.write(
    outcome === "delivered"
      ? "Отправка отмечена как доставленная; повтор с этим UUID останется заблокирован.\n"
      : "Отправка отмечена как недоставленная; для новой попытки используйте новый UUID и новое подтверждение MCP.\n",
  );
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : "Неизвестная ошибка";
  process.stderr.write(`Не удалось согласовать состояние отправки: ${message}\n`);
  process.exitCode = 1;
});
