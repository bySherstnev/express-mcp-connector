import type { StandaloneExpressSession } from "./standalone-qr-client.js";

const HEALTH_PATH = "/health";
const REGISTER_METHODS_PATH = "/api/v2/ad_integration/register_methods";

type JsonRecord = Record<string, unknown>;

export interface CtsEndpointDiagnostic {
  status: number | null;
  reachable: boolean;
  requestId: string | null;
}

export interface CtsRegistrationDiagnostic {
  health: CtsEndpointDiagnostic;
  registration: CtsEndpointDiagnostic;
  registerMethods: string[];
  conclusion:
    | "available"
    | "registration-discovery-unavailable"
    | "cts-unreachable"
    | "unexpected-response";
}

function sessionCtsHost(session: StandaloneExpressSession): string {
  const host = session.ctsPending?.host ?? session.cts?.host;
  if (!host) {
    throw new Error("CTS host is unavailable in the device session");
  }
  return host;
}

function requestId(response: Response): string | null {
  const value =
    response.headers.get("x-request-id") ??
    response.headers.get("x-correlation-id") ??
    response.headers.get("request-id");
  return value && /^[a-z0-9_.:-]{1,100}$/i.test(value) ? value : null;
}

async function probe(
  url: string,
  fetchImpl: typeof fetch,
  signal?: AbortSignal,
): Promise<{ endpoint: CtsEndpointDiagnostic; payload: unknown }> {
  try {
    const response = await fetchImpl(url, { method: "GET", signal });
    let payload: unknown = null;
    try {
      payload = await response.json();
    } catch {
      // Health checks and upstream errors are allowed to have an empty body.
    }
    return {
      endpoint: {
        status: response.status,
        reachable: true,
        requestId: requestId(response),
      },
      payload,
    };
  } catch {
    return {
      endpoint: { status: null, reachable: false, requestId: null },
      payload: null,
    };
  }
}

function parseRegisterMethods(payload: unknown): string[] {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    return [];
  }
  const result = (payload as JsonRecord).result;
  if (!result || typeof result !== "object" || Array.isArray(result)) {
    return [];
  }
  const methods = (result as JsonRecord).register_methods;
  return Array.isArray(methods)
    ? methods.filter((value): value is string => typeof value === "string")
    : [];
}

/**
 * Checks the same public registration discovery route used by eXpress 3.72.
 * The result intentionally contains no host, token, login, or response body.
 */
export async function diagnoseCtsRegistration(
  session: StandaloneExpressSession,
  options: { fetch?: typeof fetch; signal?: AbortSignal } = {},
): Promise<CtsRegistrationDiagnostic> {
  const host = sessionCtsHost(session);
  const fetchImpl = options.fetch ?? fetch;
  const [health, registration] = await Promise.all([
    probe(`https://${host}${HEALTH_PATH}`, fetchImpl, options.signal),
    probe(`https://${host}${REGISTER_METHODS_PATH}`, fetchImpl, options.signal),
  ]);
  const registerMethods = parseRegisterMethods(registration.payload);
  let conclusion: CtsRegistrationDiagnostic["conclusion"];
  if (!health.endpoint.reachable && !registration.endpoint.reachable) {
    conclusion = "cts-unreachable";
  } else if (
    registration.endpoint.status !== null &&
    registration.endpoint.status >= 500 &&
    health.endpoint.status !== null &&
    health.endpoint.status >= 200 &&
    health.endpoint.status < 300
  ) {
    conclusion = "registration-discovery-unavailable";
  } else if (
    registration.endpoint.status !== null &&
    registration.endpoint.status >= 200 &&
    registration.endpoint.status < 300 &&
    registerMethods.length > 0
  ) {
    conclusion = "available";
  } else {
    conclusion = "unexpected-response";
  }
  return {
    health: health.endpoint,
    registration: registration.endpoint,
    registerMethods,
    conclusion,
  };
}
