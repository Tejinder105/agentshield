"use client";

import { useState } from "react";

import { Button, Card, CardHeader, Input } from "@/components/ui";
import { consoleApi } from "@/lib/api";
import { formatTimestamp } from "@/lib/format";
import type { KillSwitchResponse } from "@/lib/types";

function BlastRadiusReport({ result }: { result: KillSwitchResponse }) {
  return (
    <Card>
      <CardHeader
        title="Blast radius"
        subtitle={
          result.blast_radius.length === 0
            ? "Nothing completed during the exposure window."
            : `${result.blast_radius.length} action(s) completed before containment.`
        }
      />
      {result.blast_radius.length > 0 ? (
        <ul>
          {result.blast_radius.map((entry) => (
            <li
              key={entry.entry_hash}
              className="border-b border-slate-100 px-4 py-2 text-sm last:border-b-0"
            >
              <span className="font-mono text-xs text-slate-400">#{entry.seq}</span>{" "}
              <span className="font-medium">{entry.tool_name ?? "unknown tool"}</span>{" "}
              <span className="text-slate-500">
                (session {entry.session_id ?? "unknown"}, {entry.status},{" "}
                {formatTimestamp(entry.ts)})
              </span>
            </li>
          ))}
        </ul>
      ) : null}
    </Card>
  );
}

export default function KillSwitchPage() {
  const [globalReason, setGlobalReason] = useState("");
  const [sessionId, setSessionId] = useState("");
  const [sessionReason, setSessionReason] = useState("");
  const [result, setResult] = useState<KillSwitchResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [confirmingGlobal, setConfirmingGlobal] = useState(false);
  const [busy, setBusy] = useState(false);

  async function triggerGlobal() {
    setBusy(true);
    setError(null);
    try {
      setResult(await consoleApi.killSwitchGlobal(globalReason || "manually triggered"));
      setConfirmingGlobal(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  async function triggerSession() {
    if (sessionId.trim().length === 0) {
      return;
    }
    setBusy(true);
    setError(null);
    try {
      setResult(
        await consoleApi.killSwitchSession(
          sessionId.trim(),
          sessionReason || "manually triggered",
        ),
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-lg font-semibold text-slate-900">Emergency revocation</h1>
        <p className="mt-1 text-sm text-slate-600">
          Bumps the revocation epoch, invalidating every affected capability. In-flight calls
          already past the receipt check cannot be un-sent -- see the blast-radius report below
          for what completed before containment.
        </p>
      </div>

      {error ? (
        <Card className="border-red-300 bg-red-50 p-3 text-sm text-red-800">{error}</Card>
      ) : null}

      <Card className="border-red-200">
        <CardHeader
          title="Global kill switch"
          subtitle="Invalidates every capability in every session, and drains every pending approval."
        />
        <div className="space-y-3 p-4">
          <Input
            placeholder="reason (shown in the audit log)"
            value={globalReason}
            onChange={(e) => setGlobalReason(e.target.value)}
          />
          {!confirmingGlobal ? (
            <Button variant="danger" onClick={() => setConfirmingGlobal(true)}>
              Trigger global kill switch
            </Button>
          ) : (
            <div className="flex items-center gap-2">
              <span className="text-sm text-red-800">
                This affects every session. Are you sure?
              </span>
              <Button variant="danger" onClick={triggerGlobal} disabled={busy}>
                Confirm
              </Button>
              <Button variant="ghost" onClick={() => setConfirmingGlobal(false)}>
                Cancel
              </Button>
            </div>
          )}
        </div>
      </Card>

      <Card>
        <CardHeader
          title="Session kill switch"
          subtitle="Invalidates capabilities for exactly one session, without touching others."
        />
        <div className="space-y-3 p-4">
          <Input
            placeholder="session id"
            value={sessionId}
            onChange={(e) => setSessionId(e.target.value)}
          />
          <Input
            placeholder="reason (shown in the audit log)"
            value={sessionReason}
            onChange={(e) => setSessionReason(e.target.value)}
          />
          <Button variant="danger" onClick={triggerSession} disabled={busy}>
            Trigger session kill switch
          </Button>
        </div>
      </Card>

      {result ? <BlastRadiusReport result={result} /> : null}
    </div>
  );
}
