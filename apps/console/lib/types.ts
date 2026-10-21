// Wire types mirroring `agentshield_console_api.schemas` exactly -- see
// `packages/agentshield-console-api/src/agentshield_console_api/schemas.py`.
// Kept hand-written rather than generated: the console API's surface is
// small and stable enough that a codegen step would add more ceremony than
// it would save, and any drift is caught immediately by the integration
// tests in `lib/api.test.ts` exercising real response shapes.

export type DecisionKind = "ALLOW" | "DENY" | "REQUIRE_APPROVAL";

export interface PolicyView {
  session_id: string;
  policy_text: string;
}

export interface ValidatePolicyResponse {
  valid: boolean;
  errors: string[];
}

export interface SubsumptionActionResult {
  action: string;
  outcome: "NARROWING" | "EXPANSION" | "UNPROVEN";
  detail: Record<string, unknown>;
}

export interface SubsumptionReportView {
  outcome: "NARROWING" | "EXPANSION" | "UNPROVEN";
  per_action: SubsumptionActionResult[];
}

export interface ProposePolicyResponse {
  decision: DecisionKind;
  stage: string;
  reason: string;
  applied: boolean;
  subsumption_report: SubsumptionReportView | null;
}

export interface PendingApprovalView {
  request_id: string;
  session_id: string;
  tool_name: string;
  arguments: Record<string, unknown>;
  resource_version: number;
  requested_at: number;
  status: "pending" | "approved" | "denied" | "expired";
}

export interface ReceiptView {
  payload: Record<string, unknown>;
  signature: string;
}

export interface AuditEntry {
  seq: number;
  event_type: string;
  payload: Record<string, unknown>;
  ts: number | null;
}

export interface AuditSessionResponse {
  session_id: string;
  chain_intact: boolean;
  entries: AuditEntry[];
}

export interface ReplaySessionResponse {
  session_id: string;
  chain_intact: boolean;
  final_decision: string | null;
  steps: AuditEntry[];
}

export interface BlastRadiusEntry {
  seq: number;
  entry_hash: string;
  session_id: string | null;
  tool_name: string | null;
  status: string | null;
  ts: number | null;
}

export interface KillSwitchResponse {
  scope: "global" | "session";
  reason: string;
  triggered_at: number;
  session_id: string | null;
  new_global_epoch: number | null;
  new_session_epoch: number | null;
  blast_radius: BlastRadiusEntry[];
}
