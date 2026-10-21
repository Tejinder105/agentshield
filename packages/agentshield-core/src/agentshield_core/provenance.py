"""Taint tracking and provenance for values flowing through an agent session.

A `TaintedValue` wraps any payload (text, a parsed field, a tool result)
together with a `ProvenanceNode` describing where it came from and what it was
derived from. The provenance graph is a DAG: a value computed from two
tainted inputs has two parents, and its label is the join of both.

This is what makes an audit explanation like "this argument derives from an
untrusted web page read at step 4" possible: walk the DAG backwards from the
offending argument to its source nodes.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any, Generic, TypeVar

from agentshield_core.labels import Label

T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class ProvenanceNode:
    """One node in the provenance DAG."""

    node_id: str
    source: str  # human-readable origin, e.g. "tool:read_email#msg_42"
    label: Label
    parents: tuple[ProvenanceNode, ...] = ()

    @staticmethod
    def origin(source: str, label: Label) -> ProvenanceNode:
        """A root node: a value that entered the system with no prior provenance."""
        return ProvenanceNode(node_id=str(uuid.uuid4()), source=source, label=label, parents=())

    def derive(self, source: str, extra_label: Label | None = None) -> ProvenanceNode:
        """A new node derived from this one, optionally joined with an
        additional label (e.g. a transformation that itself introduces new
        taint, such as a quarantined-LLM parse of raw bytes).
        """
        label = self.label if extra_label is None else self.label.join(extra_label)
        return ProvenanceNode(
            node_id=str(uuid.uuid4()), source=source, label=label, parents=(self,)
        )

    @staticmethod
    def combine(source: str, parents: tuple[ProvenanceNode, ...]) -> ProvenanceNode:
        """A new node derived from multiple parents; its label is the join of all of them."""
        if not parents:
            raise ValueError("combine() requires at least one parent")
        label = parents[0].label
        for p in parents[1:]:
            label = label.join(p.label)
        return ProvenanceNode(
            node_id=str(uuid.uuid4()), source=source, label=label, parents=parents
        )

    def ancestry_sources(self) -> list[str]:
        """Depth-first list of every source string in this node's ancestry,
        most recent first -- used to render denial explanations.
        """
        seen: set[str] = set()
        order: list[str] = []

        def visit(node: ProvenanceNode) -> None:
            if node.node_id in seen:
                return
            seen.add(node.node_id)
            order.append(node.source)
            for parent in node.parents:
                visit(parent)

        visit(self)
        return order

    def least_trusted_ancestor(self) -> ProvenanceNode:
        """The *origin* node (one with no parents of its own) responsible for
        the most restrictive component of this node's label.

        Note this deliberately does not compare against intermediate or self
        nodes: because `join` is a least upper bound, any derived node's
        label is, by construction, already at least as restrictive as every
        one of its ancestors (see `test_join_is_upper_bound`). Comparing
        against `self` would therefore always trivially "win" and never
        point back to an actual source. Instead this walks all the way back
        to the origin leaves and picks whichever single leaf most dominates
        the others -- the one actually responsible for the taint.

        Because restrictiveness is only a partial order, two origins can be
        mutually incomparable (e.g. one is more secret, the other less
        trustworthy). In that case this returns whichever incomparable
        maximal origin is encountered first; both are equally valid
        explanations of "a" source responsible for the current ceiling.
        """
        origins: list[ProvenanceNode] = []
        stack: list[ProvenanceNode] = [self]
        seen = {self.node_id}
        while stack:
            node = stack.pop()
            if not node.parents:
                origins.append(node)
            for parent in node.parents:
                if parent.node_id not in seen:
                    seen.add(parent.node_id)
                    stack.append(parent)
        if not origins:
            return self
        worst = origins[0]
        for candidate in origins[1:]:
            if candidate.label.is_at_least_as_restrictive_as(worst.label):
                worst = candidate
        return worst

    def explain(self) -> str:
        """A short, human-readable denial explanation."""
        worst = self.least_trusted_ancestor()
        if worst.node_id == self.node_id:
            return f"value originates directly from {self.source!r} (label={self.label})"
        return (
            f"value derives from {worst.source!r} (label={worst.label}) "
            f"via chain: {' -> '.join(self.ancestry_sources())}"
        )


@dataclass(slots=True)
class TaintedValue(Generic[T]):
    """A payload paired with its provenance."""

    value: T
    provenance: ProvenanceNode

    @property
    def label(self) -> Label:
        return self.provenance.label

    @staticmethod
    def from_source(value: T, source: str, label: Label) -> TaintedValue[T]:
        return TaintedValue(value=value, provenance=ProvenanceNode.origin(source, label))

    def derive(
        self, value: Any, source: str, extra_label: Label | None = None
    ) -> TaintedValue[Any]:
        """Produce a new TaintedValue representing a transformation of this one."""
        return TaintedValue(value=value, provenance=self.provenance.derive(source, extra_label))

    @staticmethod
    def combine(
        value: Any, source: str, inputs: tuple[TaintedValue[Any], ...]
    ) -> TaintedValue[Any]:
        parents = tuple(v.provenance for v in inputs)
        return TaintedValue(value=value, provenance=ProvenanceNode.combine(source, parents))
