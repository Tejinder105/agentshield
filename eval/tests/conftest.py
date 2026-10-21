from __future__ import annotations

from typing import Any

import pytest
from agentdojo.functions_runtime import FunctionsRuntime, make_function
from agentshield_core.labels import Confidentiality, Integrity, Label
from agentshield_core.trifecta import TrifectaLeg
from agentshield_eval.harness import function_to_tool_dict
from agentshield_eval.tool_profiles import ToolSecurityClass
from agentshield_gateway.registry import ToolSecurityProfile


def read_message() -> str:
    """Reads an untrusted inbound message.

    :return: the message text.
    """
    return "hello from an untrusted sender"


def read_secret() -> str:
    """Reads a private secret value only the user should see.

    :return: the secret value.
    """
    return "shh"


def send_message(body: str) -> str:
    """Sends a message to an external recipient.

    :param body: the message body to send.
    :return: a delivery confirmation.
    """
    return f"sent: {body}"


def return_a_float() -> float:
    """Returns a floating-point value, to exercise ledger sanitization.

    :return: a float.
    """
    return 10.5


def broken_tool() -> str:
    """A tool that always fails when invoked, for testing uncertain outcomes.

    :return: never returns -- always raises.
    """
    raise RuntimeError("boom")


@pytest.fixture
def demo_functions() -> list[Any]:
    return [read_message, read_secret, send_message, return_a_float, broken_tool]


@pytest.fixture
def demo_runtime(demo_functions: list[Any]) -> FunctionsRuntime:
    return FunctionsRuntime([make_function(fn) for fn in demo_functions])


@pytest.fixture
def demo_tool_dicts(demo_runtime: FunctionsRuntime) -> list[dict[str, Any]]:
    return [function_to_tool_dict(fn) for fn in demo_runtime.functions.values()]


@pytest.fixture
def demo_tool_classes() -> dict[str, ToolSecurityClass]:
    return {
        "read_message": ToolSecurityClass(
            profile=ToolSecurityProfile(
                ceiling=Label.top(), trifecta_leg=TrifectaLeg.UNTRUSTED_INPUT
            ),
            read_label=Label.untrusted(),
        ),
        "read_secret": ToolSecurityClass(
            profile=ToolSecurityProfile(ceiling=Label.top(), trifecta_leg=TrifectaLeg.PRIVATE_DATA),
            read_label=Label.private(),
        ),
        "send_message": ToolSecurityClass(
            profile=ToolSecurityProfile(
                ceiling=Label(
                    integrity=Integrity.TENTATIVE, confidentiality=Confidentiality.INTERNAL
                ),
                trifecta_leg=TrifectaLeg.EXTERNAL_COMMUNICATION,
            ),
        ),
        "return_a_float": ToolSecurityClass(
            profile=ToolSecurityProfile(ceiling=Label.top(), trifecta_leg=None),
        ),
        "broken_tool": ToolSecurityClass(
            profile=ToolSecurityProfile(ceiling=Label.top(), trifecta_leg=None),
        ),
    }
