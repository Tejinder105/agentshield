import { describe, expect, it } from "vitest";

import { decisionBadgeClass, formatArguments, formatTimestamp, isDecisionKind } from "./format";

describe("decisionBadgeClass", () => {
  it("returns a distinct class for each decision kind", () => {
    const allow = decisionBadgeClass("ALLOW");
    const deny = decisionBadgeClass("DENY");
    const requireApproval = decisionBadgeClass("REQUIRE_APPROVAL");
    expect(new Set([allow, deny, requireApproval]).size).toBe(3);
    expect(allow).toContain("emerald");
    expect(deny).toContain("red");
    expect(requireApproval).toContain("amber");
  });

  it("falls back to a neutral class for an unrecognized value", () => {
    expect(decisionBadgeClass("SOMETHING_ELSE")).toContain("slate");
  });
});

describe("isDecisionKind", () => {
  it("accepts exactly the three known decision kinds", () => {
    expect(isDecisionKind("ALLOW")).toBe(true);
    expect(isDecisionKind("DENY")).toBe(true);
    expect(isDecisionKind("REQUIRE_APPROVAL")).toBe(true);
    expect(isDecisionKind("allow")).toBe(false);
    expect(isDecisionKind("")).toBe(false);
  });
});

describe("formatTimestamp", () => {
  it("renders null and undefined as an em dash placeholder", () => {
    expect(formatTimestamp(null)).toBe("—");
    expect(formatTimestamp(undefined)).toBe("—");
  });

  it("renders a Unix-epoch-seconds timestamp as a non-empty date string", () => {
    const rendered = formatTimestamp(1_700_000_000);
    expect(rendered).not.toBe("—");
    expect(rendered.length).toBeGreaterThan(0);
  });
});

describe("formatArguments", () => {
  it("renders an empty arguments object as a placeholder", () => {
    expect(formatArguments({})).toBe("(no arguments)");
  });

  it("renders each key=value pair, JSON-encoding the value", () => {
    const rendered = formatArguments({ to: "alice@example.com", amount: 42 });
    expect(rendered).toBe('to="alice@example.com", amount=42');
  });
});
