import { describe, expect, it, vi } from "vitest";

import { removeTemporaryQrDirectory } from "../src/cli/temporary-qr-cleanup.js";

describe("temporary QR cleanup", () => {
  it("retries transient Windows removal failures", async () => {
    const remove = vi.fn().mockResolvedValue(undefined);

    await removeTemporaryQrDirectory("C:\\Temp\\express-login", { remove });

    expect(remove).toHaveBeenCalledWith("C:\\Temp\\express-login", {
      recursive: true,
      force: true,
      maxRetries: 5,
      retryDelay: 200,
    });
  });

  it("does not replace the original authentication error", async () => {
    const authenticationError = new Error("pairing was rejected");
    const removalError = Object.assign(new Error("resource busy"), {
      code: "EBUSY",
    });
    const warn = vi.fn();

    const operation = async (): Promise<void> => {
      try {
        throw authenticationError;
      } finally {
        await removeTemporaryQrDirectory("C:\\Temp\\express-login", {
          remove: vi.fn().mockRejectedValue(removalError),
          warn,
        });
      }
    };

    await expect(operation()).rejects.toBe(authenticationError);
    expect(warn).toHaveBeenCalledWith(
      expect.stringContaining("Удалите каталог вручную"),
    );
  });

  it("does not fail successful authentication when cleanup diagnostics fail", async () => {
    await expect(removeTemporaryQrDirectory("/tmp/express-login", {
      remove: vi.fn().mockRejectedValue(new Error("cleanup failed")),
      warn: vi.fn(() => {
        throw new Error("stderr unavailable");
      }),
    })).resolves.toBeUndefined();
  });
});
