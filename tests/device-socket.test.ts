import { describe, expect, it } from "vitest";

import type { StandaloneExpressSession } from "../src/auth/standalone-qr-client.js";
import { buildDeviceSocketUrl } from "../src/express/device-socket.js";

describe("device socket URL", () => {
  it("builds a token-free Phoenix endpoint", () => {
    const session = {
      rts: { host: "rts.synthetic.invalid", authToken: "MUST_NOT_LEAK" },
      encryptionKeys: { rts_pub_key_id: "synthetic-key-id" },
    } as StandaloneExpressSession;
    const url = new URL(
      buildDeviceSocketUrl(session, "synthetic-instance-id"),
    );

    expect(url.origin).toBe("wss://rts.synthetic.invalid");
    expect(url.pathname).toBe("/socket/user/websocket");
    expect(url.searchParams.get("key_id")).toBe("synthetic-key-id");
    expect(url.searchParams.get("version")).toBe("6");
    expect(url.searchParams.get("instance_id")).toBe(
      "synthetic-instance-id",
    );
    expect(url.toString()).not.toContain("MUST_NOT_LEAK");
  });

  it("selects the CTS host and E2E key for corporate chats", () => {
    const session = {
      cts: {
        host: "cts.synthetic.invalid",
        accessToken: "MUST_NOT_LEAK",
        active: true,
        userHuid: "synthetic-corporate-user",
        serverId: "synthetic-cts",
      },
      encryptionKeys: { cts_pub_key_id: "synthetic-cts-key-id" },
    } as StandaloneExpressSession;
    const url = new URL(
      buildDeviceSocketUrl(session, "synthetic-instance-id", "cts"),
    );

    expect(url.origin).toBe("wss://cts.synthetic.invalid");
    expect(url.searchParams.get("key_id")).toBe("synthetic-cts-key-id");
    expect(url.toString()).not.toContain("MUST_NOT_LEAK");
  });
});
