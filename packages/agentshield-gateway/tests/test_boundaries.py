import pytest
from agentshield_gateway.boundaries import (
    KeyPrincipalResolver,
    NeverRequiresApproval,
    RejectAllReceiptVerifier,
    ZeroEpochSource,
)


def test_key_principal_resolver_finds_exact_key() -> None:
    resolver = KeyPrincipalResolver()
    assert resolver.resolve({"principal": "alice"}) == "alice"


def test_key_principal_resolver_is_case_insensitive_for_header_style_keys() -> None:
    resolver = KeyPrincipalResolver()
    assert resolver.resolve({"X-Agent-Shield-Principal": "alice"}) == "alice"


def test_key_principal_resolver_returns_none_when_absent() -> None:
    resolver = KeyPrincipalResolver()
    assert resolver.resolve({}) is None


def test_key_principal_resolver_ignores_non_string_values() -> None:
    resolver = KeyPrincipalResolver()
    assert resolver.resolve({"principal": 12345}) is None


@pytest.mark.asyncio
async def test_zero_epoch_source_is_always_zero() -> None:
    source = ZeroEpochSource()
    assert await source.current_epoch("any-session") == 0
    assert await source.current_epoch("another-session") == 0


def test_never_requires_approval_is_always_false() -> None:
    policy = NeverRequiresApproval()
    assert policy.requires_approval("send_email", {}) is False


@pytest.mark.asyncio
async def test_reject_all_receipt_verifier_always_fails_closed() -> None:
    verifier = RejectAllReceiptVerifier()
    result1 = await verifier.verify(None, session_id="s1", tool_name="send_email", arguments={})
    result2 = await verifier.verify("anything-at-all", session_id="s1", tool_name="x", arguments={})
    assert result1 is False
    assert result2 is False
