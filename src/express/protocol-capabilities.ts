/**
 * Wire capabilities implemented by this connector. Compatibility is checked
 * from the data needed by an operation, not from an eXpress release number.
 */
export const EXPRESS_EVENT_ALGORITHM =
  "xsalsa20:xchacha20_aead_ietf" as const;
export const EXPRESS_LEGACY_CHAT_PROFILE = "xsalsa20:chacha20" as const;
export const EXPRESS_SIGNING_ALGORITHM = "ed25519" as const;
export const EXPRESS_DEVICE_KEY_ALGORITHM = "xsalsa20" as const;
export const EXPRESS_WIRE_PROFILE = "desktop-wire-v6" as const;

const KDC_KEY_ALGORITHMS = new Set<string>([
  EXPRESS_DEVICE_KEY_ALGORITHM,
  EXPRESS_EVENT_ALGORITHM,
]);

export function isSupportedEventAlgorithm(
  value: unknown,
): value is typeof EXPRESS_EVENT_ALGORITHM {
  return value === EXPRESS_EVENT_ALGORITHM;
}

export function isSupportedSendChatProfile(value: unknown): value is string {
  return resolveOutboundEventAlgorithm(value) !== null;
}

/**
 * `chat_list.algo` is a chat capability/profile, not necessarily the exact
 * algorithm written to each event envelope. Current corporate chats can still
 * advertise the legacy profile while new events use the authenticated AEAD
 * envelope. Keep every mapping explicit so unknown profiles fail closed.
 */
export function resolveOutboundEventAlgorithm(
  chatProfile: unknown,
): typeof EXPRESS_EVENT_ALGORITHM | null {
  switch (chatProfile) {
    case EXPRESS_LEGACY_CHAT_PROFILE:
    case EXPRESS_EVENT_ALGORITHM:
      return EXPRESS_EVENT_ALGORITHM;
    default:
      return null;
  }
}

export function isSupportedKdcKeyAlgorithm(value: unknown): value is string {
  return typeof value === "string" && KDC_KEY_ALGORITHMS.has(value);
}
