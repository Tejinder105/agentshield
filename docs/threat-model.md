# Agent Shield Threat Model

This document defines the trust boundaries, assumptions, and explicit non-goals for Agent
Shield. Every enforcement mechanism in this repository is designed against the model below;
if a proposed feature does not fit here, the threat model should be updated deliberately
rather than the feature built around an implicit, undocumented assumption.

## 1. Attacker model

The attacker is anyone who can place content into a channel the agent will read: a web page,
an email body, a document, a Slack message, or the *result* of a tool call. The attacker does
**not** need direct access to the agent's prompt, API keys, or infrastructure. This is
indirect prompt injection: the attack payload rides inside data the agent was asked to
process.

We assume the attacker:

- Knows the agent is built on an LLM and may know its system prompt, tools, and even that
  Agent Shield is in place (defense-aware / adaptive attacker, not merely a static benchmark
  payload).
- Can fully control the content of any single untrusted source the agent reads during a
  session.
- Cannot directly call tools, modify the gateway's code or configuration, or read the
  gateway's private keys.
- May attempt multi-step, patient attacks across a long-running session (e.g., first
  establishing a seemingly benign tool-call pattern, then pivoting).

## 2. Trust boundaries

```
┌─────────────────────────────────────────────────────────────────┐
│  UNTRUSTED                                                        │
│  Web pages, emails, documents, third-party tool results,          │
│  any content the agent did not originate itself                  │
└─────────────────────────────────────────────────────────────────┘
                              │  (crosses boundary via quarantine)
┌─────────────────────────────────────────────────────────────────┐
│  SEMI-TRUSTED                                                     │
│  The privileged planner LLM. Can read labels and symbolic         │
│  references. Cannot read raw untrusted bytes. Cannot directly     │
│  grant itself privilege.                                          │
└─────────────────────────────────────────────────────────────────┘
                              │  (crosses boundary via PDP)
┌─────────────────────────────────────────────────────────────────┐
│  TRUSTED, NON-LLM                                                  │
│  The reference monitor: PDP, capability broker, approval          │
│  service, revocation service, ledger. Deterministic code only.    │
└─────────────────────────────────────────────────────────────────┘
                              │  (crosses boundary via signed receipt)
┌─────────────────────────────────────────────────────────────────┐
│  HUMAN                                                             │
│  The approver. Trusted to make a correct decision about a         │
│  specific, fully-disclosed call. Not trusted to be infallible,    │
│  hence tiering, digests, and explanations.                        │
└─────────────────────────────────────────────────────────────────┘
```

Only the trusted, non-LLM layer may authorize a tool call. The planner proposes; the monitor
disposes. This is the classical reference-monitor property: the enforcement mechanism must be
tamper-proof, always invoked, and small enough to verify.

## 3. What is trusted, and why

| Component | Trust level | Rationale |
|---|---|---|
| Policy Decision Point (`agentshield-policy`) | Fully trusted | Pure, deterministic Cedar evaluation. No LLM in the call path. Fails closed on any error. |
| Capability broker (`agentshield-core`) | Fully trusted | Attenuation-only; cannot be asked to widen a grant. |
| Ledger (`agentshield-ledger`) | Trusted for integrity, not for secrecy | Anyone with filesystem/DB access can *read* it; nobody can rewrite it undetected once a checkpoint has been externally anchored. |
| Approval signing key | Trusted root of the human-approval chain | Compromise of this key is equivalent to compromising every human approver. Must be stored in an HSM/KMS in production, never in application config. |
| Privileged (planner) LLM | Semi-trusted | Can be adversarially steered by its own training/sampling, but is denied the raw bytes needed to be steered by *this session's* untrusted content, and cannot grant itself privilege regardless of what it outputs. |
| Quarantined (parser) LLM | Untrusted output, trusted boundary | Its output is structured and schema-constrained, but is treated as attacker-influenced data, not as instructions. It holds no tools. |
| Human approver | Trusted per-decision | Trusted to correctly evaluate the one call shown, not trusted to notice something hidden from them. The system's job is to show them the real argument digest, not to lean on their vigilance for things it should have already filtered. |
| MCP tool servers | Untrusted by default | Schema and description are pinned at session start and rechecked every call. A server that changes a tool's advertised behavior mid-session is treated as a supply-chain attack (rug-pull), not a configuration update. |

## 4. Core invariants the system must preserve

1. **Fail-closed.** Any exception, timeout, parse error, or unresolved identity in the
   decision pipeline resolves to `DENY`. There is no code path where an internal error
   silently becomes `ALLOW`.
2. **No LLM is the final authority.** An LLM may *propose* a policy or *parse* untrusted data,
   but the PDP's decision is made entirely by deterministic code evaluating typed arguments
   against a policy and a label lattice.
3. **Monotonic confinement.** Within a session, a policy update may only narrow the action
   space automatically. Any update that would expand it requires a human-signed receipt. An
   agent that has been fully hijacked by injected instructions still cannot grant itself a
   capability it did not already have.
4. **Untrusted content never reaches the planner as raw bytes.** It is parsed by a tool-less
   quarantined model into a fixed schema, or stored behind a symbolic reference that only the
   non-LLM orchestrator dereferences at dispatch time.
5. **The lethal trifecta is a checked invariant, not a guideline.** A session may not
   simultaneously hold (a) exposure to untrusted content, (b) access to private data, and (c)
   an external communication channel. Acquiring the third leg when the other two are already
   present is a denial, not a warning.
6. **Approval binds to the exact call.** A human's "yes" is a signature over a digest of the
   literal arguments, a resource version, and a single-use nonce — not a time-boxed blanket
   grant to call a tool again with different arguments.
7. **The ledger is tamper-evident, not tamper-proof against the operator alone.** Local
   hash-chaining and Merkle-anchoring detect any rewrite; an external, periodically published
   checkpoint is what makes a rewrite *provable* to a third party, not just detectable to the
   operator who could also rewrite the detection.
8. **Revocation is bounded-latency, not instantaneous.** A call already dispatched to a tool
   server before an epoch flip propagates may still complete. The system does not claim to
   stop it; it claims to detect, record, and report it as part of the blast radius.

## 5. Explicit non-goals

- **Agent Shield does not try to make the planner LLM immune to prompt injection.** No
  training, fine-tuning, or prompting technique is treated as a security boundary anywhere in
  this system. The 2025–2026 literature is unambiguous that in-band defenses (defensive system
  prompts, delimiters, injection classifiers) have been broken by adaptive attackers at over
  90% success rates. The planner is assumed hijackable at all times; the system's job is to
  make that irrelevant to what actually happens.
- **An injection-detection classifier is defense-in-depth only.** If included, its sole effect
  is to raise a call's approval tier. It is never wired into the `ALLOW`/`DENY` decision
  itself, because classifier-based detection is precisely the mechanism adaptive attackers have
  repeatedly defeated.
- **Agent Shield does not guarantee task utility.** A default-deny system that blocks
  legitimate work is a real failure mode (over-defense); shadow mode and fallback actions exist
  to manage this, but correctness of enforcement is always prioritized over task completion.
- **Agent Shield does not protect against a compromised gateway host.** If the machine running
  the PDP, ledger, and signing keys is itself owned by an attacker (not merely fed untrusted
  content), the reference-monitor property is void. Key management (HSM/KMS), host hardening,
  and infrastructure security are out of scope for this repository and are the operator's
  responsibility.
- **Agent Shield does not undo external side effects.** It cannot un-send an email or un-post a
  message. It bounds exposure through short TTLs and fast revocation, and it is honest about
  this in the blast-radius report rather than implying a guarantee it cannot make.
- **Agent Shield is not a general-purpose AI safety or alignment system.** It addresses
  unauthorized tool use arising from prompt injection and compromised/malicious content. It
  does not address model misalignment on tasks the user genuinely asked for.
