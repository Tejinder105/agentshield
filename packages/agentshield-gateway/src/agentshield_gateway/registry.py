"""The gateway's declared security profile for each tool: the maximum
information-flow label it may be called under (step 5), and which, if any,
lethal-trifecta leg calling it acquires (step 6).

This is deliberately separate from the Cedar policy set (step 4). Cedar
answers "is this specific call, with these arguments, permitted" against
admin-authored rules; this registry answers the structural question "what
kind of thing is this tool, security-wise" independent of any particular
call's arguments. A tool absent from this registry has no declared
ceiling or trifecta classification at all, which the pipeline treats as a
denial (see `agentshield_gateway.pipeline`) -- an *unclassified* tool is
exactly as dangerous as a *misclassified* one, so there is no permissive
default here.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from agentshield_core.labels import Label
from agentshield_core.trifecta import TrifectaLeg


@dataclass(frozen=True, slots=True)
class ToolSecurityProfile:
    ceiling: Label = field(default_factory=Label.bottom)
    trifecta_leg: TrifectaLeg | None = None


@dataclass(slots=True)
class ToolRegistry:
    profiles: dict[str, ToolSecurityProfile] = field(default_factory=dict)

    def register(self, tool_name: str, profile: ToolSecurityProfile) -> None:
        self.profiles[tool_name] = profile

    def get(self, tool_name: str) -> ToolSecurityProfile | None:
        return self.profiles.get(tool_name)
