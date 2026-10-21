import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ConsoleApiError, consoleApi } from "./api";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("consoleApi", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("getPolicy issues a GET against the session's policy endpoint", async () => {
    const fetchMock = fetch as unknown as ReturnType<typeof vi.fn>;
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ session_id: "s1", policy_text: "permit(principal, action, resource);" }),
    );

    const result = await consoleApi.getPolicy("s1");

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${consoleApi.baseUrl}/sessions/s1/policy`);
    expect(init.method).toBeUndefined(); // defaults to GET
    expect(result.session_id).toBe("s1");
  });

  it("proposePolicy issues a PUT with the candidate policy text as the body", async () => {
    const fetchMock = fetch as unknown as ReturnType<typeof vi.fn>;
    fetchMock.mockResolvedValueOnce(
      jsonResponse({
        decision: "ALLOW",
        stage: "monotonic_confinement",
        reason: "narrowing",
        applied: true,
        subsumption_report: null,
      }),
    );

    const result = await consoleApi.proposePolicy("s1", "permit(principal, action, resource);");

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${consoleApi.baseUrl}/sessions/s1/policy`);
    expect(init.method).toBe("PUT");
    expect(JSON.parse(init.body as string)).toEqual({
      policy_text: "permit(principal, action, resource);",
    });
    expect(result.applied).toBe(true);
  });

  it("approve sends the nonce and returns the signed receipt", async () => {
    const fetchMock = fetch as unknown as ReturnType<typeof vi.fn>;
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ payload: { session_id: "s1" }, signature: "deadbeef" }),
    );

    const receipt = await consoleApi.approve("req-1", "nonce-1");

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${consoleApi.baseUrl}/approvals/req-1/approve`);
    expect(JSON.parse(init.body as string)).toEqual({ nonce: "nonce-1" });
    expect(receipt.signature).toBe("deadbeef");
  });

  it("deny sends no body", async () => {
    const fetchMock = fetch as unknown as ReturnType<typeof vi.fn>;
    fetchMock.mockResolvedValueOnce(
      jsonResponse({
        request_id: "req-1",
        session_id: "s1",
        tool_name: "t",
        arguments: {},
        resource_version: 0,
        requested_at: 0,
        status: "denied",
      }),
    );

    const approval = await consoleApi.deny("req-1");

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(init.body).toBeUndefined();
    expect(approval.status).toBe("denied");
  });

  it("killSwitchGlobal posts the reason to the global endpoint", async () => {
    const fetchMock = fetch as unknown as ReturnType<typeof vi.fn>;
    fetchMock.mockResolvedValueOnce(
      jsonResponse({
        scope: "global",
        reason: "incident",
        triggered_at: 123,
        session_id: null,
        new_global_epoch: 1,
        new_session_epoch: null,
        blast_radius: [],
      }),
    );

    const result = await consoleApi.killSwitchGlobal("incident");

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${consoleApi.baseUrl}/kill-switch/global`);
    expect(JSON.parse(init.body as string)).toEqual({ reason: "incident" });
    expect(result.new_global_epoch).toBe(1);
  });

  it("throws a ConsoleApiError carrying the status code on a non-2xx response", async () => {
    const fetchMock = fetch as unknown as ReturnType<typeof vi.fn>;
    fetchMock.mockResolvedValueOnce(new Response("unknown session", { status: 404 }));

    const error = await consoleApi.getPolicy("no-such-session").catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ConsoleApiError);
    expect((error as ConsoleApiError).status).toBe(404);
    expect((error as ConsoleApiError).message).toBe("unknown session");
  });

  it("returns undefined for a 204 No Content response without parsing a body", async () => {
    const fetchMock = fetch as unknown as ReturnType<typeof vi.fn>;
    fetchMock.mockResolvedValueOnce(new Response(null, { status: 204 }));

    const result = await consoleApi.deny("req-1");
    expect(result).toBeUndefined();
  });
});
