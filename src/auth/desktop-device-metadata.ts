import os from "node:os";

import { EXPRESS_CLIENT_VERSION } from "./express-client-headers.js";

export interface DesktopDeviceMetadata {
  device: string;
  deviceSoftware: string;
  deviceHostname: string;
  manufacturer: string;
  platform: "desktop";
  locale: string;
  timezone: string;
  pushes: false;
  permissions: Record<string, never>;
}

export interface DesktopDeviceMetadataOptions {
  platform?: NodeJS.Platform;
  release?: string;
  hostname?: string;
  locale?: string;
  timezone?: string;
}

function platformIdentity(platform: NodeJS.Platform): {
  systemName: string;
  manufacturer: string;
} {
  switch (platform) {
    case "darwin":
      return { systemName: "macOS", manufacturer: "Apple" };
    case "win32":
      return { systemName: "Windows", manufacturer: "Microsoft" };
    case "linux":
      return { systemName: "Linux", manufacturer: "Linux" };
    default:
      return { systemName: platform, manufacturer: "Unknown" };
  }
}

export function createDesktopDeviceMetadata(
  options: DesktopDeviceMetadataOptions = {},
): DesktopDeviceMetadata {
  const platform = options.platform ?? process.platform;
  const identity = platformIdentity(platform);
  return {
    device: `Desktop ${EXPRESS_CLIENT_VERSION}`,
    deviceSoftware: `${identity.systemName} ${options.release ?? os.release()}`,
    deviceHostname: options.hostname ?? os.hostname(),
    manufacturer: identity.manufacturer,
    platform: "desktop",
    locale: options.locale ?? "ru",
    timezone:
      options.timezone ?? Intl.DateTimeFormat().resolvedOptions().timeZone,
    pushes: false,
    permissions: {},
  };
}
