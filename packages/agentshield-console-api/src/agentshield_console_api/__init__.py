"""The Agent Shield control-plane API: the backend behind `apps/console`.

This package administers the same lower-level services the gateway's data
path enforces against -- `agentshield-policy`, `agentshield-confinement`,
`agentshield-approvals`, `agentshield-ledger`, `agentshield-revocation` --
but deliberately does not depend on `agentshield-gateway` itself. The
architecture diagram in the plan draws `Console --> APR`, `Console -->
REV`, `Console --> Ledger` as peers of the gateway, not as a client of it,
and this package's dependency graph mirrors that exactly.
"""

from agentshield_console_api.app import create_app
from agentshield_console_api.audit import AuditEntryView, chain_intact, session_entries
from agentshield_console_api.policies import (
    PolicyRegistry,
    SessionPolicy,
    UnknownSessionError,
    ValidationResult,
)
from agentshield_console_api.replay import SessionReplay, replay_session

__all__ = [
    "create_app",
    "AuditEntryView",
    "chain_intact",
    "session_entries",
    "PolicyRegistry",
    "SessionPolicy",
    "UnknownSessionError",
    "ValidationResult",
    "SessionReplay",
    "replay_session",
]
