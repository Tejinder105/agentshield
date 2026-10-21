from __future__ import annotations

from agentshield_core.labels import Confidentiality, Integrity, Label
from agentshield_core.provenance import ProvenanceNode, TaintedValue


def test_origin_has_no_parents() -> None:
    node = ProvenanceNode.origin("tool:read_file#readme", Label.bottom())
    assert node.parents == ()
    assert node.label == Label.bottom()


def test_derive_inherits_and_joins_label() -> None:
    root = ProvenanceNode.origin("web:page_42", Label.untrusted())
    derived = root.derive("quarantine:parse_amount")
    assert derived.label == root.label
    assert derived.parents == (root,)

    derived_with_extra_taint = root.derive("transform:lowercase", extra_label=Label.private())
    assert derived_with_extra_taint.label == Label.untrusted().join(Label.private())


def test_combine_joins_all_parent_labels() -> None:
    trusted_template = ProvenanceNode.origin("template:greeting", Label.bottom())
    untrusted_name = ProvenanceNode.origin("web:contact_form", Label.untrusted())
    combined = ProvenanceNode.combine("render:email_body", (trusted_template, untrusted_name))
    assert combined.label == Label.bottom().join(Label.untrusted())
    assert combined.label == Label.untrusted()


def test_ancestry_sources_depth_first_order() -> None:
    root = ProvenanceNode.origin("web:page", Label.untrusted())
    mid = root.derive("quarantine:parse")
    leaf = mid.derive("render:body")
    sources = leaf.ancestry_sources()
    assert sources == ["render:body", "quarantine:parse", "web:page"]


def test_least_trusted_ancestor_identifies_an_unambiguously_dominant_source() -> None:
    """When one origin's label dominates every other origin's label in the
    partial order, `least_trusted_ancestor` must return exactly that origin.
    """
    trusted_root = ProvenanceNode.origin("template:greeting", Label.bottom())
    private_root = ProvenanceNode.origin("crm:contact_lookup", Label.private())
    worst_root = ProvenanceNode.origin("web:evil_page", Label.top())  # dominates everything

    combined = ProvenanceNode.combine("render:body", (trusted_root, private_root, worst_root))
    worst = combined.least_trusted_ancestor()
    assert worst.node_id == worst_root.node_id


def test_least_trusted_ancestor_returns_a_real_origin_even_when_incomparable() -> None:
    """Restrictiveness is only a partial order: a more-secret-but-trusted
    origin and a less-secret-but-untrusted origin can be mutually
    incomparable. In that case the function must still return one of the
    real origin leaves, not some intermediate or synthetic node.
    """
    secret_root = ProvenanceNode.origin(
        "db:ssn_lookup", Label(Integrity.TRUSTED, Confidentiality.SECRET)
    )
    untrusted_root = ProvenanceNode.origin("web:page", Label.untrusted())

    combined = ProvenanceNode.combine("render:body", (secret_root, untrusted_root))
    worst = combined.least_trusted_ancestor()
    assert worst.node_id in {secret_root.node_id, untrusted_root.node_id}
    assert worst.parents == ()  # must be a true origin, never the combined node itself


def test_least_trusted_ancestor_of_a_pure_origin_is_itself() -> None:
    origin = ProvenanceNode.origin("web:page", Label.untrusted())
    assert origin.least_trusted_ancestor().node_id == origin.node_id


def test_explain_mentions_the_responsible_source() -> None:
    root = ProvenanceNode.origin("web:evil_page", Label.untrusted())
    derived = root.derive("quarantine:parse_email_body")
    explanation = derived.explain()
    assert "web:evil_page" in explanation


def test_tainted_value_from_source_and_derive() -> None:
    tv = TaintedValue.from_source("hello", "web:page", Label.untrusted())
    assert tv.label == Label.untrusted()

    derived = tv.derive("HELLO", source="transform:upper")
    assert derived.value == "HELLO"
    assert derived.label == Label.untrusted()


def test_tainted_value_combine() -> None:
    a = TaintedValue.from_source("Alice", "crm:contact", Label.private())
    b = TaintedValue.from_source("hi there", "web:page", Label.untrusted())
    combined = TaintedValue.combine("hi there, Alice", "render:greeting", (a, b))
    assert combined.label == Label.private().join(Label.untrusted())
