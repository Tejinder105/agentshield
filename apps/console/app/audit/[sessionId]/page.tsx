"use client";

import { useParams } from "next/navigation";
import { useCallback, useEffect, useState } from "react";

import { Badge, Button, Card, CardHeader } from "@/components/ui";
import { consoleApi } from "@/lib/api";
import { decisionBadgeClass, formatTimestamp } from "@/lib/format";
import type { AuditEntry, AuditSessionResponse, ReplaySessionResponse } from "@/lib/types";

function ChainIntegrityBadge({ intact }: { intact: boolean }) {
  return (
    <Badge
      className={
        intact
          ? "border-emerald-300 bg-emerald-100 text-emerald-800"
          : "border-red-300 bg-red-100 text-red-800"
      }
    >
      {intact ? "hash chain intact" : "TAMPERING DETECTED"}
    </Badge>
  );
}

function EntryRow({ entry }: { entry: AuditEntry }) {
  const decision = entry.payload["decision"];
  const provenancePath = entry.payload["provenance_path"];
  return (
    <li className="border-b border-slate-100 px-4 py-3 last:border-b-0">
      <div className="flex items-center gap-2">
        <span className="font-mono text-xs text-slate-400">#{entry.seq}</span>
        <span className="text-sm font-medium text-slate-900">{entry.event_type}</span>
        {typeof decision === "string" ? (
          <span
            className={
              "rounded-full border px-2 py-0.5 text-xs font-medium " +
              decisionBadgeClass(decision)
            }
          >
            {decision}
          </span>
        ) : null}
        <span className="ml-auto text-xs text-slate-400">{formatTimestamp(entry.ts)}</span>
      </div>
      {typeof entry.payload["reason"] === "string" ? (
        <p className="mt-1 text-sm text-slate-600">{String(entry.payload["reason"])}</p>
      ) : null}
      {typeof provenancePath === "string" ? (
        <p className="mt-1 rounded-md bg-amber-50 p-2 text-xs text-amber-800">
          <span className="font-medium">Provenance: </span>
          {provenancePath}
        </p>
      ) : null}
    </li>
  );
}

export default function AuditExplorerPage() {
  const params = useParams<{ sessionId: string }>();
  const sessionId = params.sessionId;

  const [audit, setAudit] = useState<AuditSessionResponse | null>(null);
  const [replay, setReplay] = useState<ReplaySessionResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setAudit(await consoleApi.getAuditSession(sessionId));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, [sessionId]);

  useEffect(() => {
    void load();
  }, [load]);

  async function handleReplay() {
    setError(null);
    try {
      setReplay(await consoleApi.replaySession(sessionId));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-lg font-semibold text-slate-900">
          Audit explorer &mdash; <span className="font-mono">{sessionId}</span>
        </h1>
        <p className="mt-1 text-sm text-slate-600">
          Every decision and outcome recorded for this session, in the tamper-evident ledger&apos;s
          own append order.
        </p>
      </div>

      {error ? (
        <Card className="border-red-300 bg-red-50 p-3 text-sm text-red-800">{error}</Card>
      ) : null}

      {loading ? (
        <p className="text-sm text-slate-500">Loading…</p>
      ) : audit ? (
        <>
          <div className="flex items-center justify-between">
            <ChainIntegrityBadge intact={audit.chain_intact} />
            <Button variant="secondary" onClick={handleReplay}>
              Replay this session
            </Button>
          </div>

          {replay ? (
            <Card>
              <CardHeader
                title="Deterministic replay"
                subtitle="Reconstructed exclusively from the ledger, with the hash chain re-verified."
              />
              <div className="flex items-center gap-3 p-4 text-sm">
                <ChainIntegrityBadge intact={replay.chain_intact} />
                <span className="text-slate-600">
                  Final decision:{" "}
                  <span
                    className={
                      "rounded-full border px-2 py-0.5 text-xs font-medium " +
                      decisionBadgeClass(replay.final_decision ?? "")
                    }
                  >
                    {replay.final_decision ?? "none"}
                  </span>
                </span>
                <span className="text-slate-400">{replay.steps.length} steps</span>
              </div>
            </Card>
          ) : null}

          <Card>
            <CardHeader title="Timeline" />
            {audit.entries.length === 0 ? (
              <p className="p-4 text-sm text-slate-500">No ledger entries for this session.</p>
            ) : (
              <ul>
                {audit.entries.map((entry) => (
                  <EntryRow key={entry.seq} entry={entry} />
                ))}
              </ul>
            )}
          </Card>
        </>
      ) : null}
    </div>
  );
}
