import type { DecisionKind } from "./types";

/** Tailwind utility classes for a small colored decision badge -- kept as
 * a pure function so it is trivially unit-testable without rendering.
 */
export function decisionBadgeClass(decision: string): string {
  switch (decision) {
    case "ALLOW":
      return "bg-emerald-100 text-emerald-800 border-emerald-300";
    case "DENY":
      return "bg-red-100 text-red-800 border-red-300";
    case "REQUIRE_APPROVAL":
      return "bg-amber-100 text-amber-800 border-amber-300";
    default:
      return "bg-slate-100 text-slate-700 border-slate-300";
  }
}

export function isDecisionKind(value: string): value is DecisionKind {
  return value === "ALLOW" || value === "DENY" || value === "REQUIRE_APPROVAL";
}

/** Renders a Unix-epoch-seconds timestamp (the ledger's own unit, per
 * `agentshield_ledger.ledger.Ledger.append`) as a locale-formatted string,
 * or a placeholder when absent.
 */
export function formatTimestamp(ts: number | null | undefined): string {
  if (ts === null || ts === undefined) {
    return "—";
  }
  return new Date(ts * 1000).toLocaleString();
}

/** A one-line, deterministic rendering of a tool call's arguments for
 * compact display (the approval queue's full-argument-detail view uses
 * the raw object directly instead; this is for list rows and audit
 * timelines).
 */
export function formatArguments(args: Record<string, unknown>): string {
  const entries = Object.entries(args);
  if (entries.length === 0) {
    return "(no arguments)";
  }
  return entries.map(([key, value]) => `${key}=${JSON.stringify(value)}`).join(", ");
}
