# Agent Shield

Securing action-taking AI agents against prompt injection and unauthorized tool use through
deterministic, out-of-band enforcement: least privilege, tool authorization, trusted-input
labeling, human approval, tamper-evident audit logging, and emergency revocation.

See [`PLAN.md`](PLAN.md) for the full architecture, diagrams, tech stack, and phased
implementation roadmap, and [`docs/threat-model.md`](docs/threat-model.md) for the trust
boundaries and non-goals every component below is built against.

## Repository layout

```
packages/
  agentshield-core/           label lattice, provenance, capabilities, Decision type, trifecta
  agentshield-policy/         Cedar PDP, MCP schema generation, subsumption checking
  agentshield-ledger/         hash chain, Merkle tree, signed checkpoints, verify CLI
  agentshield-approvals/      signed approval receipts, pending queue, tiering
  agentshield-revocation/     epoch counters, kill switch, blast-radius reporting
  agentshield-gateway/        FastAPI + MCP proxy, the 8-step decision pipeline
  agentshield-sdk/            framework adapters, dual-LLM quarantine
  agentshield-confinement/    policy synthesis + monotonic confinement
  agentshield-observability/  OpenTelemetry GenAI spans, shadow mode
apps/console/                 Next.js control plane
eval/                         AgentDojo / AgentDyn harness, adaptive attacks, ablation
infra/                        SQL grants, Helm chart
docs/                         threat model, operator guide
```

## Quickstart

```powershell
# Python workspace
uv sync --all-packages --dev
uv run pytest

# Infra
docker compose up -d postgres redis

# Console
cd apps/console
npm install
npm run dev
```

## Design principle

Prompt injection is not solved inside the model. Every enforcement decision in this repository
is made by deterministic, non-LLM code at the tool-call boundary. LLMs appear in exactly two
places — synthesizing a candidate policy and parsing untrusted data into a fixed schema — and
neither can grant itself privilege. See the core thesis in [`PLAN.md`](PLAN.md) for the
research this is built on.
