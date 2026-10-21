from __future__ import annotations

from agentshield_core.decision import DecisionKind
from agentshield_gateway.egress import (
    EgressPolicy,
    extract_urls,
    find_secret,
    host_allowed,
)


def test_aws_access_key_is_detected() -> None:
    matched = find_secret("leak AKIAIOSFODNN7EXAMPLE please", EgressPolicy().secret_patterns)
    assert matched is not None


def test_private_key_pem_is_detected() -> None:
    body = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"
    matched = find_secret(body, EgressPolicy().secret_patterns)
    assert matched is not None


def test_ordinary_prose_is_not_a_secret() -> None:
    assert (
        find_secret("please email alice about the invoice", EgressPolicy().secret_patterns) is None
    )


def test_inspect_denies_a_nested_secret() -> None:
    policy = EgressPolicy()
    decision = policy.inspect(
        "send_email", {"to": "a@b.com", "body": {"note": "ghp_abcdefghijklmnopqrstuvwxyz"}}
    )
    assert decision.kind is DecisionKind.DENY
    assert decision.stage == "egress"


def test_url_allowlist_refuses_an_unknown_host() -> None:
    policy = EgressPolicy(allowed_hosts=frozenset({"example.com"}))
    decision = policy.inspect("get_webpage", {"url": "https://evil.example/steal"})
    assert decision.kind is DecisionKind.DENY
    assert "allowlist" in decision.reason


def test_url_allowlist_accepts_an_exact_or_subdomain_host() -> None:
    policy = EgressPolicy(allowed_hosts=frozenset({"example.com"}))
    assert (
        policy.inspect("get_webpage", {"url": "https://example.com/a"}).kind is DecisionKind.ALLOW
    )
    assert (
        policy.inspect("get_webpage", {"url": "https://docs.example.com/a"}).kind
        is DecisionKind.ALLOW
    )


def test_unconfigured_allowlist_permits_any_url() -> None:
    policy = EgressPolicy(allowed_hosts=None)
    assert (
        policy.inspect("get_webpage", {"url": "https://anywhere.example"}).kind
        is DecisionKind.ALLOW
    )


def test_empty_allowlist_refuses_every_url() -> None:
    policy = EgressPolicy(allowed_hosts=frozenset())
    assert policy.inspect("get_webpage", {"url": "https://example.com"}).kind is DecisionKind.DENY


def test_extract_urls_finds_well_known_keys_and_urlish_strings() -> None:
    urls = extract_urls(
        {
            "href": "https://a.example",
            "note": "see https://b.example/x",
            "nested": {"url": "http://c.example"},
        }
    )
    assert "https://a.example" in urls
    assert "http://c.example" in urls


def test_host_allowed_rejects_a_url_without_a_host() -> None:
    assert host_allowed("not-a-url", frozenset({"example.com"})) is False
