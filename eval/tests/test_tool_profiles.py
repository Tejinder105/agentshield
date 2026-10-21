from __future__ import annotations

import pytest
from agentdojo.task_suite.load_suites import get_suite
from agentshield_eval.tool_profiles import SUITE_PROFILES, profiles_for_suite


@pytest.mark.parametrize("suite_name", ["workspace", "slack", "travel", "banking"])
def test_every_real_suite_tool_has_a_classification(suite_name: str) -> None:
    """Regression guard: if a future `agentdojo` upgrade adds or renames a
    tool in one of the four default suites, this fails loudly instead of
    the gateway silently denying every call to the new tool for lacking a
    registered security profile.
    """
    suite = get_suite("v1.2.2", suite_name)
    classified = profiles_for_suite(suite_name)
    suite_tool_names = {function.name for function in suite.tools}
    assert suite_tool_names <= classified.keys()


def test_unknown_suite_name_raises_key_error() -> None:
    with pytest.raises(KeyError):
        profiles_for_suite("not-a-real-suite")


def test_every_classified_tool_has_a_profile_and_a_label() -> None:
    for suite_name, classified in SUITE_PROFILES.items():
        for tool_name, tool_class in classified.items():
            assert tool_class.profile is not None, f"{suite_name}.{tool_name} missing a profile"
            assert tool_class.read_label is not None, (
                f"{suite_name}.{tool_name} missing a read label"
            )
