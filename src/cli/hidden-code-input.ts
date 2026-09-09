export async function readHiddenSixDigitCode(
  _argv: readonly string[],
): Promise<string> {
  if (!process.stdin.isTTY || !process.stdin.setRawMode) {
    throw new Error(
      "Запустите команду в интерактивном терминале для скрытого ввода кода",
    );
  }

  process.stdout.write("Введите шестизначный код CTS: ");
  const wasRaw = process.stdin.isRaw;
  process.stdin.setRawMode(true);
  process.stdin.resume();

  try {
    return await new Promise<string>((resolve, reject) => {
      let value = "";
      const onData = (chunk: Buffer): void => {
        for (const byte of chunk) {
          if (byte === 3) {
            process.stdin.off("data", onData);
            reject(new Error("Ввод кода отменён"));
            return;
          }
          if (byte === 10 || byte === 13) {
            process.stdin.off("data", onData);
            resolve(value);
            return;
          }
          if (byte === 8 || byte === 127) {
            value = value.slice(0, -1);
            continue;
          }
          const character = String.fromCharCode(byte);
          if (/\d/.test(character) && value.length < 6) {
            value += character;
          }
        }
      };
      process.stdin.on("data", onData);
    });
  } finally {
    process.stdin.setRawMode(wasRaw);
    process.stdin.pause();
    process.stdout.write("\n");
  }
}
