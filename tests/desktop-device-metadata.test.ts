import { describe, expect, it } from "vitest";

import { createDesktopDeviceMetadata } from "../src/auth/desktop-device-metadata.js";

describe("createDesktopDeviceMetadata", () => {
  it("describes a Windows desktop without relying on a Windows test host", () => {
    expect(createDesktopDeviceMetadata({
      platform: "win32",
      release: "10.0.26100",
      hostname: "OFFICE-PC",
      timezone: "Europe/Moscow",
    })).toMatchObject({
      device: "Desktop 3.72.37",
      deviceSoftware: "Windows 10.0.26100",
      deviceHostname: "OFFICE-PC",
      manufacturer: "Microsoft",
      platform: "desktop",
      timezone: "Europe/Moscow",
    });
  });

  it("keeps the official-looking macOS metadata", () => {
    expect(createDesktopDeviceMetadata({
      platform: "darwin",
      release: "25.5.0",
      hostname: "Mac",
    })).toMatchObject({
      deviceSoftware: "macOS 25.5.0",
      manufacturer: "Apple",
    });
  });

  it("supports Linux through the same desktop protocol", () => {
    expect(createDesktopDeviceMetadata({
      platform: "linux",
      release: "6.8.0",
      hostname: "workstation",
    })).toMatchObject({
      deviceSoftware: "Linux 6.8.0",
      manufacturer: "Linux",
    });
  });
});
