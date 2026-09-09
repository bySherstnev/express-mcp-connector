import { describe, expect, it } from "vitest";

import { createExpressDesktopUserAgent } from "../src/auth/express-client-headers.js";

describe("createExpressDesktopUserAgent", () => {
  it("uses a Windows desktop user agent on Windows", () => {
    const userAgent = createExpressDesktopUserAgent("win32");
    expect(userAgent).toContain("Windows NT 10.0; Win64; x64");
    expect(userAgent).toContain("eXpress/3.72.37");
    expect(userAgent).not.toContain("Macintosh");
  });

  it("uses the existing macOS user agent on macOS", () => {
    expect(createExpressDesktopUserAgent("darwin"))
      .toContain("Macintosh; Intel Mac OS X 10_15_7");
  });
});
