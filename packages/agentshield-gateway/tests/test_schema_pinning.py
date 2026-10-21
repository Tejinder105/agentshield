from agentshield_gateway.schema_pinning import PinnedToolSet, digest_tool

SEND_EMAIL = {
    "name": "send_email",
    "description": "Send an email",
    "inputSchema": {"type": "object"},
}


def test_pin_captures_a_digest_per_tool() -> None:
    pinned = PinnedToolSet.pin([SEND_EMAIL])
    assert "send_email" in pinned.digests
    assert pinned.digests["send_email"] == digest_tool(SEND_EMAIL)


def test_check_passes_for_unchanged_schema() -> None:
    pinned = PinnedToolSet.pin([SEND_EMAIL])
    assert pinned.check("send_email", SEND_EMAIL)


def test_check_fails_when_description_changes() -> None:
    pinned = PinnedToolSet.pin([SEND_EMAIL])
    mutated = {**SEND_EMAIL, "description": "Send an email to anyone, including externally"}
    assert not pinned.check("send_email", mutated)


def test_check_fails_when_input_schema_changes() -> None:
    pinned = PinnedToolSet.pin([SEND_EMAIL])
    mutated = {
        **SEND_EMAIL,
        "inputSchema": {"type": "object", "properties": {"cc": {"type": "string"}}},
    }
    assert not pinned.check("send_email", mutated)


def test_check_fails_for_a_never_pinned_tool() -> None:
    pinned = PinnedToolSet.pin([SEND_EMAIL])
    assert not pinned.check("delete_account", SEND_EMAIL)


def test_check_fails_when_current_schema_is_unavailable() -> None:
    pinned = PinnedToolSet.pin([SEND_EMAIL])
    assert not pinned.check("send_email", None)


def test_key_order_does_not_affect_the_digest() -> None:
    reordered = dict(reversed(list(SEND_EMAIL.items())))
    assert digest_tool(SEND_EMAIL) == digest_tool(reordered)


def test_pin_ignores_entries_without_a_string_name() -> None:
    pinned = PinnedToolSet.pin([SEND_EMAIL, {"description": "no name field"}, {"name": 123}])
    assert list(pinned.digests.keys()) == ["send_email"]
