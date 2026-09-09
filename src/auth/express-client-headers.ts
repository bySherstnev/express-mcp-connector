const configuredVersion = process.env.EXPRESS_CLIENT_VERSION?.trim();
if (configuredVersion && !/^\d+\.\d+\.\d+(?:\.\d+)?$/.test(configuredVersion)) {
  throw new Error("EXPRESS_CLIENT_VERSION has an invalid format");
}

/** Client identity sent to endpoints that require app_version metadata. */
export const EXPRESS_CLIENT_VERSION = configuredVersion || "3.72.37";

export function createExpressDesktopUserAgent(
  platform: NodeJS.Platform = process.platform,
  version: string = EXPRESS_CLIENT_VERSION,
): string {
  const system = platform === "win32"
    ? "Windows NT 10.0; Win64; x64"
    : platform === "linux"
      ? "X11; Linux x86_64"
      : "Macintosh; Intel Mac OS X 10_15_7";
  return `Mozilla/5.0 (${system}) ` +
  `AppleWebKit/537.36 (KHTML, like Gecko) eXpress/${version} ` +
  "Chrome/142.0.7444.235 Electron/39.2.7 Safari/537.36";
}

export const EXPRESS_DESKTOP_USER_AGENT = createExpressDesktopUserAgent();

export const EXPRESS_JSON_HEADERS: Readonly<Record<string, string>> = {
  Accept: "application/json, text/plain, */*",
  "Accept-Language": "ru",
  "User-Agent": EXPRESS_DESKTOP_USER_AGENT,
};
