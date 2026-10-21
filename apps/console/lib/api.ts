import type {
  AuditSessionResponse,
  KillSwitchResponse,
  PendingApprovalView,
  PolicyView,
  ProposePolicyResponse,
  ReceiptView,
  ReplaySessionResponse,
  ValidatePolicyResponse,
} from "./types";

// The console talks to `agentshield-console-api` over plain HTTP; this is
// the one place that base URL is read, so every page and component stays
// agnostic of where the API actually lives.
export const CONSOLE_API_BASE_URL =
  process.env.NEXT_PUBLIC_CONSOLE_API_URL ?? "http://localhost:8001";

export class ConsoleApiError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "ConsoleApiError";
    this.status = status;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${CONSOLE_API_BASE_URL}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
  });
  if (!response.ok) {
    const body = await response.text();
    throw new ConsoleApiError(response.status, body || response.statusText);
  }
  if (response.status === 204) {
    return undefined as T;
  }
  return (await response.json()) as T;
}

export const consoleApi = {
  baseUrl: CONSOLE_API_BASE_URL,

  getPolicy(sessionId: string): Promise<PolicyView> {
    return request<PolicyView>(`/sessions/${encodeURIComponent(sessionId)}/policy`);
  },

  registerPolicy(
    sessionId: string,
    body: { tools: Record<string, unknown>[]; policy_text: string },
  ): Promise<PolicyView> {
    return request<PolicyView>(`/sessions/${encodeURIComponent(sessionId)}/policy`, {
      method: "POST",
      body: JSON.stringify(body),
    });
  },

  validatePolicy(sessionId: string, policyText: string): Promise<ValidatePolicyResponse> {
    return request<ValidatePolicyResponse>(
      `/sessions/${encodeURIComponent(sessionId)}/policy/validate`,
      { method: "POST", body: JSON.stringify({ policy_text: policyText }) },
    );
  },

  proposePolicy(sessionId: string, policyText: string): Promise<ProposePolicyResponse> {
    return request<ProposePolicyResponse>(`/sessions/${encodeURIComponent(sessionId)}/policy`, {
      method: "PUT",
      body: JSON.stringify({ policy_text: policyText }),
    });
  },

  listApprovals(): Promise<PendingApprovalView[]> {
    return request<PendingApprovalView[]>("/approvals");
  },

  approve(requestId: string, nonce: string): Promise<ReceiptView> {
    return request<ReceiptView>(`/approvals/${encodeURIComponent(requestId)}/approve`, {
      method: "POST",
      body: JSON.stringify({ nonce }),
    });
  },

  deny(requestId: string): Promise<PendingApprovalView> {
    return request<PendingApprovalView>(`/approvals/${encodeURIComponent(requestId)}/deny`, {
      method: "POST",
    });
  },

  approvalsStreamUrl(): string {
    return `${CONSOLE_API_BASE_URL}/approvals/stream`;
  },

  getAuditSession(sessionId: string): Promise<AuditSessionResponse> {
    return request<AuditSessionResponse>(`/audit/sessions/${encodeURIComponent(sessionId)}`);
  },

  replaySession(sessionId: string): Promise<ReplaySessionResponse> {
    return request<ReplaySessionResponse>(
      `/audit/sessions/${encodeURIComponent(sessionId)}/replay`,
    );
  },

  killSwitchGlobal(reason: string): Promise<KillSwitchResponse> {
    return request<KillSwitchResponse>("/kill-switch/global", {
      method: "POST",
      body: JSON.stringify({ reason }),
    });
  },

  killSwitchSession(sessionId: string, reason: string): Promise<KillSwitchResponse> {
    return request<KillSwitchResponse>(
      `/kill-switch/sessions/${encodeURIComponent(sessionId)}`,
      { method: "POST", body: JSON.stringify({ reason }) },
    );
  },
};
