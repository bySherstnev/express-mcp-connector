import { describe, expect, it } from "vitest";

import {
  EXPRESS_EVENT_ALGORITHM,
  EXPRESS_LEGACY_CHAT_PROFILE,
  EXPRESS_WIRE_PROFILE,
  isSupportedSendChatProfile,
  isSupportedEventAlgorithm,
  isSupportedKdcKeyAlgorithm,
  resolveOutboundEventAlgorithm,
} from "../src/express/protocol-capabilities.js";

describe("eXpress wire capability checks", () => {
  it("describes compatibility by wire profile rather than release number", () => {
    expect(EXPRESS_WIRE_PROFILE).toBe("desktop-wire-v6");
    expect(EXPRESS_WIRE_PROFILE).not.toMatch(/^3\.72/);
  });

  it("accepts only implemented event and key algorithms", () => {
    expect(isSupportedEventAlgorithm(EXPRESS_EVENT_ALGORITHM)).toBe(true);
    expect(isSupportedEventAlgorithm("future-cipher")).toBe(false);
    expect(isSupportedKdcKeyAlgorithm("xsalsa20")).toBe(true);
    expect(isSupportedKdcKeyAlgorithm("future-key-wrap")).toBe(false);
  });

  it("recognizes the observed compatible chat profiles", () => {
    expect(isSupportedSendChatProfile(EXPRESS_LEGACY_CHAT_PROFILE)).toBe(true);
    expect(
      isSupportedSendChatProfile("xsalsa20:xchacha20_aead_ietf"),
    ).toBe(true);
    expect(isSupportedSendChatProfile(null)).toBe(false);
    expect(isSupportedSendChatProfile("future-chat-profile")).toBe(false);
    expect(resolveOutboundEventAlgorithm(EXPRESS_LEGACY_CHAT_PROFILE)).toBe(
      EXPRESS_EVENT_ALGORITHM,
    );
    expect(resolveOutboundEventAlgorithm(EXPRESS_EVENT_ALGORITHM)).toBe(
      EXPRESS_EVENT_ALGORITHM,
    );
    expect(resolveOutboundEventAlgorithm("future-chat-profile")).toBeNull();
  });
});
