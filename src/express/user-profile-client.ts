import type { StandaloneExpressSession } from "../auth/standalone-qr-client.js";
import {
  resolveExpressConnection,
  type ExpressConnectionKind,
} from "./connection.js";

type JsonRecord = Record<string, unknown>;
const MAX_HUIDS_PER_REQUEST = 100;
const MAX_HUID_LENGTH = 300;

export interface ExpressUserProfile {
  userHuid: string;
  name: string | null;
}

function asRecord(value: unknown, context: string): JsonRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`Invalid ${context} response`);
  }
  return value as JsonRecord;
}

function optionalRecord(value: unknown): JsonRecord | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as JsonRecord)
    : null;
}

function profileName(value: unknown): string | null {
  return typeof value === "string" && value.trim().length > 0
    ? value.trim()
    : null;
}

function validHuid(value: string): boolean {
  return value.length > 0 && value.length <= MAX_HUID_LENGTH && !/[\u0000-\u001f\u007f]/u.test(value);
}

function addCorporateProfiles(
  payload: JsonRecord,
  requested: ReadonlySet<string>,
  profiles: Map<string, ExpressUserProfile>,
): void {
  if (!Array.isArray(payload.result)) {
    throw new Error("Invalid corporate profile response");
  }
  for (const groupValue of payload.result) {
    const group = asRecord(groupValue, "corporate profile group");
    if (!Array.isArray(group.cts_profiles)) {
      continue;
    }
    for (const profileValue of group.cts_profiles) {
      const profile = asRecord(profileValue, "corporate profile");
      if (typeof profile.user_huid !== "string" || !requested.has(profile.user_huid)) {
        continue;
      }
      profiles.set(profile.user_huid, {
        userHuid: profile.user_huid,
        name: profileName(profile.name),
      });
    }
  }
}

function addPersonalProfiles(
  payload: JsonRecord,
  requested: ReadonlySet<string>,
  profiles: Map<string, ExpressUserProfile>,
): void {
  const result = asRecord(payload.result, "personal profile result");
  if (!Array.isArray(result.profiles)) {
    throw new Error("Invalid personal profile response");
  }
  for (const profileValue of result.profiles) {
    const profile = asRecord(profileValue, "personal profile");
    if (typeof profile.user_huid !== "string" || !requested.has(profile.user_huid)) {
      continue;
    }
    const corporate = optionalRecord(profile.cts_public_profile);
    const personal = optionalRecord(profile.rts_profile);
    profiles.set(profile.user_huid, {
      userHuid: profile.user_huid,
      name: profileName(corporate?.name) ?? profileName(personal?.name),
    });
  }
}

/** Resolves authenticated message-author HUIDs through the selected eXpress directory. */
export async function fetchExpressUserProfiles(
  session: StandaloneExpressSession,
  huids: readonly string[],
  options: {
    fetch?: typeof fetch;
    signal?: AbortSignal;
    connection?: ExpressConnectionKind;
  } = {},
): Promise<Map<string, ExpressUserProfile>> {
  const connectionKind = options.connection ?? "rts";
  const connection = resolveExpressConnection(session, connectionKind);
  const uniqueHuids = [...new Set(huids.filter(validHuid))];
  const profiles = new Map<string, ExpressUserProfile>();
  const fetchImpl = options.fetch ?? fetch;

  for (let offset = 0; offset < uniqueHuids.length; offset += MAX_HUIDS_PER_REQUEST) {
    const batch = uniqueHuids.slice(offset, offset + MAX_HUIDS_PER_REQUEST);
    const requested = new Set(batch);
    const path = connectionKind === "cts"
      ? "/api/v1/phonebook/cts_profiles/query"
      : "/api/v3/phonebook/profiles/query";
    let response: Response;
    try {
      response = await fetchImpl(new URL(path, `https://${connection.host}`), {
        method: "POST",
        headers: {
          Authorization: `Bearer ${connection.authToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ huids: batch }),
        signal: options.signal,
      });
    } catch {
      throw new Error("eXpress user profile request failed");
    }
    if (!response.ok) {
      throw new Error(`eXpress user profiles returned HTTP ${response.status}`);
    }
    let payload: JsonRecord;
    try {
      payload = asRecord(await response.json(), "user profile");
    } catch (error) {
      if (error instanceof Error && error.message.startsWith("Invalid")) {
        throw error;
      }
      throw new Error("eXpress user profiles returned invalid JSON");
    }
    if (payload.status !== "ok") {
      throw new Error("eXpress user profile request was rejected");
    }
    if (connectionKind === "cts") {
      addCorporateProfiles(payload, requested, profiles);
    } else {
      addPersonalProfiles(payload, requested, profiles);
    }
  }
  return profiles;
}
