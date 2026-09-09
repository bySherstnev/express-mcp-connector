import { describe, expect, it, vi } from "vitest";

import { diagnoseCtsRegistration } from "../src/auth/cts-registration-diagnostics.js";
import type { StandaloneExpressSession } from "../src/auth/standalone-qr-client.js";

const session = {
  ctsPending: {
    host: "cts.synthetic.invalid",
    temporaryToken: "SYNTHETIC_TEMP_TOKEN",
  },
} as StandaloneExpressSession;

describe("CTS registration diagnostics", () => {
  it("identifies failed registration discovery on a reachable CTS", async () => {
    const fetchMock = vi.fn<typeof fetch>(async (url) => {
      if (String(url).endsWith("/health")) {
        return new Response(null, { status: 204 });
      }
      return new Response(JSON.stringify({ status: "error" }), {
        status: 500,
        headers: {
          "content-type": "application/json",
          "x-request-id": "synthetic-request-id",
        },
      });
    });

    const result = await diagnoseCtsRegistration(session, {
      fetch: fetchMock,
    });

    expect(result).toEqual({
      health: { status: 204, reachable: true, requestId: null },
      registration: {
        status: 500,
        reachable: true,
        requestId: "synthetic-request-id",
      },
      registerMethods: [],
      conclusion: "registration-discovery-unavailable",
    });
  });

  it("returns the configured official registration methods", async () => {
    const fetchMock = vi.fn<typeof fetch>(async (url) => {
      if (String(url).endsWith("/health")) {
        return new Response(null, { status: 204 });
      }
      return new Response(
        JSON.stringify({
          status: "ok",
          result: { register_methods: ["qr", "email", "openid"] },
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    });

    const result = await diagnoseCtsRegistration(session, {
      fetch: fetchMock,
    });

    expect(result.conclusion).toBe("available");
    expect(result.registerMethods).toEqual(["qr", "email", "openid"]);
  });

  it("does not expose an invalid correlation header", async () => {
    const fetchMock = vi.fn<typeof fetch>(async () =>
      new Response(JSON.stringify({ status: "error" }), {
        status: 500,
        headers: { "x-request-id": "unsafe value with spaces" },
      }),
    );

    const result = await diagnoseCtsRegistration(session, {
      fetch: fetchMock,
    });

    expect(result.registration.requestId).toBeNull();
  });
});
