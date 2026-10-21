"""Agent Shield security kernel.

Zero-I/O enforcement primitives: the label lattice, provenance tracking,
capability tokens, the `Decision` type, and the lethal-trifecta invariant.
This package is deliberately small and dependency-light so it can be
reviewed by hand -- it is the part of the system every other guarantee rests
on.
"""

from agentshield_core.capabilities import Capability, Caveat, arg_at_most, arg_equals, arg_in
from agentshield_core.decision import (
    Decision,
    DecisionKind,
    Obligation,
    ObligationKind,
    most_severe,
)
from agentshield_core.labels import Confidentiality, Integrity, Label, join_all
from agentshield_core.provenance import ProvenanceNode, TaintedValue
from agentshield_core.quotas import Quota, QuotaStore
from agentshield_core.trifecta import TrifectaLeg, TrifectaState

__all__ = [
    "Capability",
    "Caveat",
    "Quota",
    "QuotaStore",
    "arg_at_most",
    "arg_equals",
    "arg_in",
    "Decision",
    "DecisionKind",
    "Obligation",
    "ObligationKind",
    "most_severe",
    "Confidentiality",
    "Integrity",
    "Label",
    "join_all",
    "ProvenanceNode",
    "TaintedValue",
    "TrifectaLeg",
    "TrifectaState",
]
