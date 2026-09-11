import { rm } from "node:fs/promises";

export interface TemporaryQrCleanupDependencies {
  remove?: typeof rm;
  warn?: (message: string) => void;
}

/**
 * Removes one-time QR material without allowing a Windows file lock or another
 * cleanup failure to replace the result of the authentication operation.
 */
export async function removeTemporaryQrDirectory(
  directory: string,
  dependencies: TemporaryQrCleanupDependencies = {},
): Promise<void> {
  const remove = dependencies.remove ?? rm;
  const warn = dependencies.warn ?? ((message: string) => process.stderr.write(message));
  try {
    await remove(directory, {
      recursive: true,
      force: true,
      maxRetries: 5,
      retryDelay: 200,
    });
  } catch (error) {
    const reason = error instanceof Error ? `: ${error.message}` : "";
    try {
      warn(
        `Предупреждение: не удалось удалить временный QR-код ${directory}${reason}. Удалите каталог вручную.\n`,
      );
    } catch {
      // Cleanup diagnostics must never replace the authentication result.
    }
  }
}
