import { createServer, type Server } from "node:http";
import { once } from "node:events";
import type { AddressInfo } from "node:net";
import sodium from "libsodium-wrappers-sumo";
import { beforeAll, describe, expect, it } from "vitest";

import { refreshCtsSession } from "../src/auth/cts-token-refresh.js";
import { confirmPendingCtsSession } from "../src/auth/cts-session-confirmation.js";
import {
  confirmCtsEmailCode,
  requestCtsEmailCode,
} from "../src/auth/cts-email-auth.js";
import {
  completeQrRegistration,
  type StandaloneExpressSession,
} from "../src/auth/standalone-qr-client.js";
import { createQrRegistrationState } from "../src/auth/standalone-qr-registration.js";
import {
  fetchRtsServerPublicKey,
  prepareRtsRequestIdentity,
  uploadRtsRequestIdentity,
} from "../src/auth/rts-session-bootstrap.js";
import { fetchHistoryPage } from "../src/express/history-client.js";
import { fetchEventInfo } from "../src/express/event-info-client.js";
import { fetchKdcPublicKeys } from "../src/express/kdc-public-keys.js";
import { fetchExpressUserProfiles } from "../src/express/user-profile-client.js";
import { diagnoseCtsRegistration } from "../src/auth/cts-registration-diagnostics.js";

let session: StandaloneExpressSession;

beforeAll(async () => {
  await sodium.ready;
  const signing = sodium.crypto_sign_keypair();
  session = await prepareRtsRequestIdentity({
    version: 1,
    createdAt: "2026-01-01T00:00:00.000Z",
    rts: {
      host: "rts.synthetic.invalid",
      authToken: "SYNTHETIC_RTS_TOKEN",
      expiresAt: null,
      userHuid: "synthetic-user",
      serverId: "synthetic-rts",
    },
    cts: {
      host: "cts.synthetic.invalid",
      accessToken: "SYNTHETIC_ACCESS_TOKEN",
      refreshToken: "SYNTHETIC_REFRESH_TOKEN",
      expiresIn: 3600,
      userHuid: "synthetic-user",
      serverId: "synthetic-cts",
      active: true,
    },
    ctsPending: {
      host: "cts.synthetic.invalid",
      temporaryToken: "SYNTHETIC_TEMP_TOKEN",
    },
    ctsEmailPending: {
      host: "cts.synthetic.invalid",
      registrationId: "synthetic-email-registration",
      email: "person@example.invalid",
    },
    device: {
      udid: "synthetic-udid",
      registrationId: "synthetic-registration",
      signingKeyId: "synthetic-signing-key",
      signingAlgorithm: signing.keyType,
      signingPublicKey: sodium.to_base64(
        signing.publicKey, sodium.base64_variants.ORIGINAL,
      ),
      signingPrivateKey: sodium.to_base64(
        signing.privateKey, sodium.base64_variants.ORIGINAL,
      ),
    },
    encryptionKeys: { rts_key_algo: "xsalsa20", rts_pub_key_id: "synthetic-key" },
  });
});

async function listen(server: Server): Promise<string> {
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

async function close(server: Server): Promise<void> {
  server.closeAllConnections();
  await new Promise<void>((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  });
}

/** Real fetch redirect handling, with synthetic data and loopback servers only. */
async function withRedirect(
  status: number,
  operation: (fetchImpl: typeof fetch) => Promise<void>,
): Promise<void> {
  const forwardedRequests: string[] = [];
  const destination = createServer(async (request, response) => {
    let body = "";
    for await (const chunk of request) body += chunk;
    forwardedRequests.push(body);
    response.writeHead(500);
    response.end();
  });
  const destinationOrigin = await listen(destination);
  const source = createServer((request, response) => {
    request.resume();
    response.writeHead(status, { Location: `${destinationOrigin}/capture` });
    response.end();
  });
  try {
    const sourceOrigin = await listen(source);
    const fetchImpl: typeof fetch = (input, init) => {
      const requested = new URL(String(input));
      expect(requested.protocol).toBe("https:");
      expect(requested.hostname).toMatch(/^(rts|cts)\.synthetic\.invalid$/);
      // Only the test transport changes the endpoint; keep the caller's policy.
      return fetch(new URL(requested.pathname + requested.search, sourceOrigin), {
        ...init,
        signal: AbortSignal.timeout(5_000),
      });
    };
    await operation(fetchImpl);
    expect(forwardedRequests).toEqual([]);
  } finally {
    await Promise.all([close(source), close(destination)]);
  }
}

describe("HTTP credential redirect protection", () => {
  it.each([307, 308])("does not forward a refresh token after HTTP %i", async status => {
    await withRedirect(status, async fetchImpl => {
      await expect(refreshCtsSession(session, { fetch: fetchImpl }))
        .rejects.toThrow("CTS token refresh request failed");
      expect(session.cts?.refreshToken).toBe("SYNTHETIC_REFRESH_TOKEN");
    });
  });

  const operations: Array<[string, (fetchImpl: typeof fetch) => Promise<unknown>]> = [
    ["QR approval", async fetchImpl => completeQrRegistration({
      initialRtsHost: "rts.synthetic.invalid",
      state: await createQrRegistrationState(),
      device: {
        device: "Synthetic desktop",
        deviceSoftware: "Synthetic OS",
        deviceHostname: null,
        manufacturer: "Synthetic",
        platform: "desktop",
        locale: "en",
        timezone: "UTC",
      },
      fetch: fetchImpl,
    })],
    ["CTS confirmation", fetchImpl => confirmPendingCtsSession(session, { fetch: fetchImpl })],
    ["email request", fetchImpl => requestCtsEmailCode(session, "person@example.invalid", { fetch: fetchImpl })],
    ["email confirmation", fetchImpl => confirmCtsEmailCode(session, "123456", { fetch: fetchImpl })],
    ["signing key upload", fetchImpl => uploadRtsRequestIdentity(session, fetchImpl)],
    ["server public key", fetchImpl => fetchRtsServerPublicKey(session, fetchImpl)],
    ["history", fetchImpl => fetchHistoryPage(session, {
      groupChatId: "synthetic-chat",
      direction: "backward",
      limit: 1,
    }, { fetch: fetchImpl })],
    ["event lookup", fetchImpl => fetchEventInfo(session, ["synthetic-sync"], { fetch: fetchImpl })],
    ["public key lookup", fetchImpl => fetchKdcPublicKeys(session, ["synthetic-key"], { fetch: fetchImpl })],
    ["profiles", fetchImpl => fetchExpressUserProfiles(session, ["synthetic-user"], { fetch: fetchImpl })],
  ];

  it.each(operations)("does not follow a redirect during %s", async (_name, operation) => {
    await withRedirect(307, async fetchImpl => {
      await expect(operation(fetchImpl)).rejects.toThrow(/(?:request|upload) failed$/);
    });
  });

  it("does not diagnose a redirected server as the configured CTS", async () => {
    await withRedirect(302, async fetchImpl => {
      const result = await diagnoseCtsRegistration(session, { fetch: fetchImpl });
      expect(result.conclusion).toBe("cts-unreachable");
    });
  });
});
