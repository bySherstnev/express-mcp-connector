import { describe, expect, it } from "vitest";

import { ConnectorPolicyGuard } from "../src/policy/connector-policy-guard.js";

describe("ConnectorPolicyGuard", () => {
  it.each([
    "chats.discover",
    "history.read",
    "keys.read",
    "message.send",
  ] as const)("allows the explicitly scoped operation %s", (operation) => {
    const guard = new ConnectorPolicyGuard();

    expect(() => guard.assertAllowed(operation)).not.toThrow();
  });

  it.each([
    "message.edit",
    "message.delete",
    "message.forward",
    "message.react",
    "attachment.upload",
    "chat.invite",
    "chat.settings.update",
  ])("rejects the mutating operation %s", (operation) => {
    const guard = new ConnectorPolicyGuard();

    expect(() => guard.assertAllowed(operation)).toThrow(/not allowed|denied/i);
  });

  it.each([
    "attachments.download",
    "contacts.export",
    "browser.execute",
    "unknown.operation",
    "",
  ])("fails closed for the unknown operation %j", (operation) => {
    const guard = new ConnectorPolicyGuard();

    expect(() => guard.assertAllowed(operation)).toThrow(/not allowed|denied/i);
  });
});
