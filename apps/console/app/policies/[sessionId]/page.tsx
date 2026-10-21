"use client";

import { useParams } from "next/navigation";
import { useCallback, useEffect, useState } from "react";

import { Button, Card, CardHeader, Textarea } from "@/components/ui";
import { consoleApi, ConsoleApiError } from "@/lib/api";
import { decisionBadgeClass } from "@/lib/format";
import type { ProposePolicyResponse, ValidatePolicyResponse } from "@/lib/types";

const DEFAULT_TOOLS_JSON = `[
  {
    "name": "send_email",
    "description": "Send an email on the user's behalf",
    "inputSchema": {
      "type": "object",
      "properties": { "to": { "type": "string" }, "body": { "type": "string" } },
      "required": ["to", "body"]
    }
  }
]`;

export default function PolicyEditorPage() {
  const params = useParams<{ sessionId: string }>();
  const sessionId = params.sessionId;

  const [loading, setLoading] = useState(true);
  const [registered, setRegistered] = useState(false);
  const [policyText, setPolicyText] = useState("");
  const [toolsJson, setToolsJson] = useState(DEFAULT_TOOLS_JSON);
  const [initialPolicyText, setInitialPolicyText] = useState(
    "permit(principal, action, resource) when { context.input.to == \"alice@example.com\" };",
  );
  const [validation, setValidation] = useState<ValidatePolicyResponse | null>(null);
  const [proposal, setProposal] = useState<ProposePolicyResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const policy = await consoleApi.getPolicy(sessionId);
      setPolicyText(policy.policy_text);
      setRegistered(true);
    } catch (err) {
      if (err instanceof ConsoleApiError && err.status === 404) {
        setRegistered(false);
      } else {
        setError(err instanceof Error ? err.message : String(err));
      }
    } finally {
      setLoading(false);
    }
  }, [sessionId]);

  useEffect(() => {
    void load();
  }, [load]);

  async function handleRegister() {
    setBusy(true);
    setError(null);
    try {
      const tools = JSON.parse(toolsJson) as Record<string, unknown>[];
      await consoleApi.registerPolicy(sessionId, { tools, policy_text: initialPolicyText });
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  async function handleValidate() {
    setBusy(true);
    setError(null);
    setProposal(null);
    try {
      setValidation(await consoleApi.validatePolicy(sessionId, policyText));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  async function handleApply() {
    setBusy(true);
    setError(null);
    setValidation(null);
    try {
      const result = await consoleApi.proposePolicy(sessionId, policyText);
      setProposal(result);
      if (result.applied) {
        await load();
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  if (loading) {
    return <p className="text-sm text-slate-500">Loading…</p>;
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-lg font-semibold text-slate-900">
          Policy editor &mdash; <span className="font-mono">{sessionId}</span>
        </h1>
        <p className="mt-1 text-sm text-slate-600">
          Every update is proposed through monotonic confinement: a proven narrowing of the
          session&apos;s current action space auto-applies, everything else is left unapplied
          and requires human approval.
        </p>
      </div>

      {error ? (
        <Card className="border-red-300 bg-red-50 p-4 text-sm text-red-800">{error}</Card>
      ) : null}

      {!registered ? (
        <Card>
          <CardHeader
            title="Register this session"
            subtitle="No policy is registered for this session id yet. Register its tools and an initial policy to start administering it."
          />
          <div className="space-y-3 p-4">
            <label className="block text-xs font-medium text-slate-700">
              Tools (MCP <code>tools/list</code> JSON)
              <Textarea
                rows={8}
                value={toolsJson}
                onChange={(e) => setToolsJson(e.target.value)}
                className="mt-1"
              />
            </label>
            <label className="block text-xs font-medium text-slate-700">
              Initial policy (Cedar)
              <Textarea
                rows={4}
                value={initialPolicyText}
                onChange={(e) => setInitialPolicyText(e.target.value)}
                className="mt-1"
              />
            </label>
            <Button onClick={handleRegister} disabled={busy}>
              Register
            </Button>
          </div>
        </Card>
      ) : (
        <Card>
          <CardHeader title="Current policy" subtitle="Cedar policy text" />
          <div className="space-y-3 p-4">
            <Textarea
              rows={14}
              value={policyText}
              onChange={(e) => setPolicyText(e.target.value)}
            />
            <div className="flex gap-2">
              <Button variant="secondary" onClick={handleValidate} disabled={busy}>
                Validate
              </Button>
              <Button onClick={handleApply} disabled={busy}>
                Propose update
              </Button>
            </div>

            {validation ? (
              <div
                className={
                  "rounded-md border p-3 text-sm " +
                  (validation.valid
                    ? "border-emerald-300 bg-emerald-50 text-emerald-800"
                    : "border-red-300 bg-red-50 text-red-800")
                }
                data-testid="validation-result"
              >
                {validation.valid ? (
                  "Valid Cedar policy against this session's schema."
                ) : (
                  <ul className="list-inside list-disc">
                    {validation.errors.map((err, i) => (
                      <li key={i}>{err}</li>
                    ))}
                  </ul>
                )}
              </div>
            ) : null}

            {proposal ? (
              <div className="space-y-2 rounded-md border border-slate-200 p-3 text-sm">
                <div className="flex items-center gap-2">
                  <span className={"rounded-full border px-2 py-0.5 text-xs font-medium " + decisionBadgeClass(proposal.decision)}>
                    {proposal.decision}
                  </span>
                  <span className="text-slate-700">{proposal.reason}</span>
                </div>
                {proposal.subsumption_report ? (
                  <div className="rounded-md bg-slate-50 p-2 text-xs text-slate-600">
                    <p className="font-medium">
                      Subsumption outcome: {proposal.subsumption_report.outcome}
                    </p>
                    <ul className="mt-1 list-inside list-disc">
                      {proposal.subsumption_report.per_action.map((action) => (
                        <li key={action.action}>
                          {action.action}: {action.outcome}
                        </li>
                      ))}
                    </ul>
                  </div>
                ) : null}
              </div>
            ) : null}
          </div>
        </Card>
      )}
    </div>
  );
}
