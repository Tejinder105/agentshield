# Deploying and operating Agent Shield

This is the operator-facing companion to `docs/threat-model.md`. It
covers how to bring the reference monitor up, how to verify that a
binary you are about to run is one this project actually produced, and
what to do when something goes wrong.

## Topology

A production deployment is four processes plus two data stores:

| Process | Package | Role |
| --- | --- | --- |
| Gateway | `agentshield-gateway` | The PEP. Mediates every `tools/call`. |
| Console API | `agentshield-console-api` | Control plane: policies, approvals, audit, kill switch. |
| Console UI | `apps/console` | Next.js operator UI. Talks only to the console API. |
| Verify CLI | `agentshield-ledger` (`agentshield-verify`) | Offline auditor. Needs no credentials and trusts no server. |
| Postgres 16 | -- | Append-only audit ledger. Application role is `INSERT`/`SELECT` only. |
| Redis | -- | Pending-approval queue and revocation epoch counter. |

The planner LLM, the quarantined parser, and every MCP tool server sit
*outside* this topology. Agent Shield never embeds them.

## Local bring-up

```
docker compose up --build
```

Postgres is initialized from `infra/sql/001_audit_grants.sql`. The
`agentshield_app` role cannot `UPDATE` or `DELETE` an audit row; if a
deployment ever needs retention pruning it must go through the
tombstone table, which is itself an audited event.

The console UI (`apps/console`) expects the console API at
`NEXT_PUBLIC_CONSOLE_API_URL` (default `http://localhost:8001`). Run
the API with:

```
uv run uvicorn agentshield_console_api.serve:app --factory --port 8001
```

and the UI with `npm run dev` from `apps/console`.

## Kubernetes

```
helm upgrade --install agentshield infra/helm/agentshield \
  --set image.tag=v0.1.0 \
  --set image.repository=ghcr.io/<org>/agentshield/agentshield-gateway
```

The chart:

- Runs the gateway as UID 10001, read-only root, all capabilities dropped.
- Expects a pre-created `agentshield-postgres` secret with `url` and
  `password` keys. Do not put the ledger signing key, the approval
  signing key, or the Postgres password in `values.yaml`.
- Defaults `shadowMode: false`. Flip it to `true` for the first week
  of a new deployment so operators can see what *would* have been
  blocked before enforcing (see the threat model's "over-defense is
  the real failure mode" risk).
- Sets `verifySignatures: true`. An admission controller that honors
  that flag (e.g. a cluster with Sigstore policy-controller) should
  refuse an image this workflow did not sign.

## Signed releases

Every `v*` tag builds every workspace wheel, signs each one with
cosign keyless (GitHub OIDC -- no long-lived signing key lives in this
repo), attaches the wheels and their `.cosign.bundle` files to the
GitHub Release, and signs the gateway image at its digest.

Verify a wheel before installing it:

```
cosign verify-blob \
  --bundle agentshield_gateway-0.1.0-py3-none-any.whl.cosign.bundle \
  --certificate-identity-regexp 'https://github.com/.+/.github/workflows/release.yml@refs/tags/v.+' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  agentshield_gateway-0.1.0-py3-none-any.whl
```

Verify the gateway image:

```
cosign verify \
  --certificate-identity-regexp 'https://github.com/.+/.github/workflows/release.yml@refs/tags/v.+' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/<org>/agentshield/agentshield-gateway@sha256:<digest>
```

An artifact without a matching bundle is not a release. Do not
`--skip-verify` your way around a missing signature.

## Egress and quotas

These are the two production controls that are *not* Cedar policies:

- **Secret-pattern scanning** is always on. A tool argument that
  matches an AWS key, a GitHub PAT, a Slack token, a PEM private key,
  an OpenAI key, or a live Stripe key is denied at stage `egress`
  regardless of what Cedar said.
- **URL allowlisting** is off until you configure
  `EgressPolicy(allowed_hosts=frozenset({...}))`. An empty frozenset
  means "refuse every URL"; `None` means "URL allowlisting is not
  configured".
- **Per-capability quotas** live on `QuotaStore`. Register a
  `Quota(max_calls=..., max_spend=...)` against a capability id at
  grant time. Quotas are consumed only when a call is authorized to
  proceed, so a flood of denials cannot burn a session's remaining
  budget. Spend is integer minor units, never a float.

## Fail-closed under load

The gateway's decision pipeline converts any exception from the PDP,
the egress checker, or the approval-tiering policy into a `DENY` with
a ledger entry. The test module
`packages/agentshield-gateway/tests/test_harden.py` floods those paths
with concurrent calls and asserts every outcome is a denial -- that is
the load/failure coverage the plan asks for. Re-run it as part of any
release candidate:

```
uv run pytest packages/agentshield-gateway/tests/test_harden.py
```

## Emergency revocation

The console's kill-switch page (and `POST /kill-switch` /
`POST /sessions/{id}/kill-switch` on the console API) flips the
revocation epoch and drains pending approvals. In-flight calls that
have already passed the receipt check cannot be un-sent; the
blast-radius report lists every `tool_outcome` that completed during
the exposure window. That honesty is load-bearing -- do not paper over
an empty blast-radius report after a real incident.

## Keys

| Key | Where it lives | Compromise means |
| --- | --- | --- |
| Ledger Ed25519 signing key | HSM / KMS, never application config | An attacker can mint a well-formed checkpoint. The hash chain and any previously-anchored root still detect rewritten history. |
| Approval Ed25519 signing key | HSM / KMS, never application config | Equivalent to compromising every human approver. Rotate immediately and drain the pending queue. |
| Postgres `agentshield_app` password | Kubernetes secret | Read/append the ledger. Cannot rewrite it without the owner role. |

## What this deployment does not do

- It does not run an injection-detection classifier as an
  authoritative decision. The threat model is explicit about this.
- It does not embed a planner LLM. Shadow mode still evaluates the
  same deterministic pipeline; it only changes whether a denial is
  enforced or logged.
- It does not make the first synthesized policy trustworthy. High-risk
  sessions still need a human to review the initial Cedar text (see
  `docs/threat-model.md` "Honest risks").
