"use client";

import { useMutation } from "@tanstack/react-query";
import { useEffect, useState } from "react";

import { Button, Card, CardHeader, Input } from "@/components/ui";
import { consoleApi } from "@/lib/api";
import { formatTimestamp } from "@/lib/format";
import type { PendingApprovalView } from "@/lib/types";

export default function ApprovalsPage() {
  const [approvals, setApprovals] = useState<PendingApprovalView[]>([]);
  const [connected, setConnected] = useState(false);
  const [nonces, setNonces] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);

  // The live feed: the browser's native `EventSource` already parses the
  // `event: snapshot` / `data: <json>` SSE wire format for us (see
  // `agentshield_console_api.sse.approval_queue_events`), so no manual
  // frame parsing is needed here at all.
  useEffect(() => {
    const source = new EventSource(consoleApi.approvalsStreamUrl());
    source.addEventListener("snapshot", (event) => {
      setConnected(true);
      try {
        setApprovals(JSON.parse((event as MessageEvent).data) as PendingApprovalView[]);
      } catch {
        // A malformed frame is ignored; the next snapshot self-corrects.
      }
    });
    source.onerror = () => setConnected(false);
    return () => source.close();
  }, []);

  const approveMutation = useMutation({
    mutationFn: ({ requestId, nonce }: { requestId: string; nonce: string }) =>
      consoleApi.approve(requestId, nonce),
    onError: (err: unknown) => setError(err instanceof Error ? err.message : String(err)),
  });

  const denyMutation = useMutation({
    mutationFn: (requestId: string) => consoleApi.deny(requestId),
    onError: (err: unknown) => setError(err instanceof Error ? err.message : String(err)),
  });

  const pending = approvals.filter((a) => a.status === "pending");

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold text-slate-900">Live approval queue</h1>
          <p className="mt-1 text-sm text-slate-600">
            Every tool call tiered as requiring human sign-off, shown with its full original
            arguments.
          </p>
        </div>
        <span
          className={
            "text-xs font-medium " + (connected ? "text-emerald-600" : "text-slate-400")
          }
        >
          {connected ? "● live" : "○ connecting…"}
        </span>
      </div>

      {error ? (
        <Card className="border-red-300 bg-red-50 p-3 text-sm text-red-800">{error}</Card>
      ) : null}

      {pending.length === 0 ? (
        <p className="text-sm text-slate-500" data-testid="empty-state">
          No pending approvals.
        </p>
      ) : (
        <div className="space-y-3">
          {pending.map((approval) => (
            <Card key={approval.request_id} data-testid="approval-row">
              <CardHeader
                title={`${approval.tool_name} — session ${approval.session_id}`}
                subtitle={`requested ${formatTimestamp(approval.requested_at)}`}
              />
              <div className="space-y-3 p-4">
                <pre className="overflow-x-auto rounded-md bg-slate-50 p-2 text-xs text-slate-700">
                  {JSON.stringify(approval.arguments, null, 2)}
                </pre>
                <div className="flex items-end gap-2">
                  <label className="flex-1 text-xs font-medium text-slate-700">
                    Approval nonce
                    <Input
                      placeholder="a unique nonce for this receipt"
                      value={nonces[approval.request_id] ?? ""}
                      onChange={(e) =>
                        setNonces((prev) => ({
                          ...prev,
                          [approval.request_id]: e.target.value,
                        }))
                      }
                      className="mt-1"
                    />
                  </label>
                  <Button
                    onClick={() =>
                      approveMutation.mutate({
                        requestId: approval.request_id,
                        nonce: nonces[approval.request_id] || crypto.randomUUID(),
                      })
                    }
                    disabled={approveMutation.isPending}
                  >
                    Approve
                  </Button>
                  <Button
                    variant="danger"
                    onClick={() => denyMutation.mutate(approval.request_id)}
                    disabled={denyMutation.isPending}
                  >
                    Deny
                  </Button>
                </div>
              </div>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
