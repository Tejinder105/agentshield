"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { Button, Card, CardHeader, Input } from "@/components/ui";

export default function DashboardPage() {
  const router = useRouter();
  const [sessionId, setSessionId] = useState("");

  function goTo(path: (id: string) => string) {
    if (sessionId.trim().length === 0) {
      return;
    }
    router.push(path(sessionId.trim()));
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-lg font-semibold text-slate-900">Session lookup</h1>
        <p className="mt-1 text-sm text-slate-600">
          Enter a session id to open its policy editor or audit explorer. The live approval
          queue and the kill switch are session-independent and always available from the nav
          bar above.
        </p>
      </div>

      <Card className="max-w-md">
        <CardHeader title="Open a session" />
        <div className="space-y-3 p-4">
          <Input
            placeholder="session id, e.g. s1"
            value={sessionId}
            onChange={(e) => setSessionId(e.target.value)}
          />
          <div className="flex gap-2">
            <Button onClick={() => goTo((id) => `/policies/${id}`)}>Policy editor</Button>
            <Button
              variant="secondary"
              onClick={() => goTo((id) => `/audit/${id}`)}
            >
              Audit explorer
            </Button>
          </div>
        </div>
      </Card>
    </div>
  );
}
