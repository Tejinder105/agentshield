"""Egress controls: argument-level secret-pattern scanning and URL
allowlisting on outbound tools.

These are the two controls the plan names under "Egress and budget
controls" that are *not* already expressed by Cedar, the label lattice,
or the trifecta invariant:

- A Cedar policy that permits `send_email` to alice@example.com still
  has no opinion about whether the *body* contains an AWS key the
  session just read. Secret-pattern scanning is the last look at the
  actual argument bytes before they leave.
- A Cedar policy that permits `get_webpage` still has no opinion about
  whether the URL is `https://evil.example` rather than an allowlisted
  host. URL allowlisting is the structural counterpart of that.

Neither control is an injection classifier. A match is a hard denial,
not a signal that raises an approval tier -- classifier-based detection
is exactly the non-goal the threat model calls out.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from agentshield_core.decision import Decision

STAGE = "egress"

#: Patterns that, if they appear in any string argument, mean the call
#: is about to exfiltrate a credential. Kept deliberately tight: a
#: false positive here is a denied call, so each pattern must name a
#: specific, well-known secret format rather than a generic "looks
#: random" heuristic.
DEFAULT_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"sk-(?:proj-)?[A-Za-z0-9]{20,}"),
    re.compile(r"sk_live_[A-Za-z0-9]{10,}"),
    re.compile(r"rk_live_[A-Za-z0-9]{10,}"),
)

_URL_ARG_KEYS = frozenset({"url", "href", "uri", "endpoint", "webhook", "link", "callback"})
_URLISH = re.compile(r"^https?://", re.IGNORECASE)


def _walk_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        found: list[str] = []
        for inner in value.values():
            found.extend(_walk_strings(inner))
        return found
    if isinstance(value, (list, tuple)):
        found = []
        for inner in value:
            found.extend(_walk_strings(inner))
        return found
    return []


def find_secret(text: str, patterns: tuple[re.Pattern[str], ...]) -> str | None:
    """Return the first matching pattern's source, or `None`."""
    for pattern in patterns:
        if pattern.search(text):
            return pattern.pattern
    return None


def extract_urls(arguments: Mapping[str, Any]) -> list[str]:
    """Every argument that is either a well-known URL field or a string
    that already looks like an `http(s)://` URL.
    """
    urls: list[str] = []
    for key, value in arguments.items():
        if isinstance(value, str) and (key.lower() in _URL_ARG_KEYS or _URLISH.match(value)):
            urls.append(value)
        elif isinstance(value, dict):
            urls.extend(extract_urls(value))
        elif isinstance(value, (list, tuple)):
            for item in value:
                if isinstance(item, str) and _URLISH.match(item):
                    urls.append(item)
    return urls


def host_allowed(url: str, allowed_hosts: frozenset[str]) -> bool:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if not host:
        return False
    if host in allowed_hosts:
        return True
    return any(host.endswith(f".{allowed}") for allowed in allowed_hosts)


@dataclass(frozen=True, slots=True)
class EgressPolicy:
    """The egress check the pipeline consults. `allowed_hosts=None`
    means URL allowlisting is not configured (every URL is accepted);
    an *empty* frozenset means every URL is refused. Secret scanning is
    always on.
    """

    secret_patterns: tuple[re.Pattern[str], ...] = DEFAULT_SECRET_PATTERNS
    allowed_hosts: frozenset[str] | None = None

    def inspect(self, tool_name: str, arguments: Mapping[str, Any]) -> Decision:
        for text in _walk_strings(dict(arguments)):
            matched = find_secret(text, self.secret_patterns)
            if matched is not None:
                return Decision.deny(
                    f"argument to {tool_name!r} matched a secret pattern; "
                    "refusing to let a credential leave the session",
                    stage=STAGE,
                )
        if self.allowed_hosts is not None:
            for url in extract_urls(arguments):
                if not host_allowed(url, self.allowed_hosts):
                    return Decision.deny(
                        f"url {url!r} on tool {tool_name!r} is not on the egress allowlist",
                        stage=STAGE,
                    )
        return Decision.allow("egress checks passed", stage=STAGE)


@dataclass(frozen=True, slots=True)
class PermitAllEgress:
    """The fail-open-on-egress default used when a deployment has not
    configured any egress policy. Secret scanning still runs: a
    credential in an argument is never a legitimate tool input.
    """

    inner: EgressPolicy = field(default_factory=EgressPolicy)

    def inspect(self, tool_name: str, arguments: Mapping[str, Any]) -> Decision:
        return self.inner.inspect(tool_name, arguments)
