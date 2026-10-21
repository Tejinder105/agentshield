from agentshield_ledger.verify.merkle import (
    MerkleTree,
    empty_root,
    leaf_hash,
    node_hash,
    verify_inclusion,
)
from hypothesis import given
from hypothesis import strategies as st


def test_empty_tree_root_is_the_rfc6962_empty_hash() -> None:
    tree = MerkleTree.build([])
    assert tree.root == empty_root()
    assert tree.size == 0


def test_single_leaf_root_is_its_leaf_hash() -> None:
    tree = MerkleTree.build([b"only"])
    assert tree.root == leaf_hash(b"only")
    assert tree.size == 1


def test_two_leaves_root_is_a_single_node_hash() -> None:
    tree = MerkleTree.build([b"a", b"b"])
    assert tree.root == node_hash(leaf_hash(b"a"), leaf_hash(b"b"))


def test_cve_2012_2459_regression_odd_leaf_count_is_not_duplicated() -> None:
    """The historical bug: naively pairing an unpaired trailing node with a
    *copy of itself* makes `[a, b, c]` and `[a, b, c, c]` produce the same
    root, letting an attacker splice in a duplicate leaf undetected. This
    implementation promotes the lone node instead, so the two trees MUST
    have different roots.
    """
    three = MerkleTree.build([b"a", b"b", b"c"])
    four_with_duplicate = MerkleTree.build([b"a", b"b", b"c", b"c"])
    assert three.root != four_with_duplicate.root


def test_promoted_node_root_equals_promotion_by_hand() -> None:
    # 3 leaves: level0 = [h(a), h(b), h(c)]; level1 = [node(h(a),h(b)), h(c)] (promoted);
    # level2 = [node(node(h(a),h(b)), h(c))]
    tree = MerkleTree.build([b"a", b"b", b"c"])
    expected = node_hash(node_hash(leaf_hash(b"a"), leaf_hash(b"b")), leaf_hash(b"c"))
    assert tree.root == expected


def test_leaf_and_node_hashes_use_disjoint_domains() -> None:
    # A leaf hash of some bytes must never collide with a node hash of two
    # (possibly adversarially chosen) other byte strings, by construction
    # of the 0x00/0x01 prefix domain separation.
    assert leaf_hash(b"\x01" + b"x" * 10) != node_hash(b"x" * 5, b"x" * 5)


def test_changing_any_leaf_changes_the_root() -> None:
    leaves = [b"a", b"b", b"c", b"d", b"e"]
    original = MerkleTree.build(leaves)
    for i in range(len(leaves)):
        mutated = list(leaves)
        mutated[i] = mutated[i] + b"!"
        assert MerkleTree.build(mutated).root != original.root


def test_inclusion_proof_round_trips_for_every_index() -> None:
    leaves = [f"leaf-{i}".encode() for i in range(13)]  # deliberately odd/awkward size
    tree = MerkleTree.build(leaves)
    for i, leaf in enumerate(leaves):
        proof = tree.inclusion_proof(i)
        assert verify_inclusion(tree.root, tree.size, i, leaf, proof)


def test_inclusion_proof_rejects_wrong_leaf_data() -> None:
    leaves = [b"a", b"b", b"c", b"d", b"e"]
    tree = MerkleTree.build(leaves)
    proof = tree.inclusion_proof(2)
    assert not verify_inclusion(tree.root, tree.size, 2, b"not-c", proof)


def test_inclusion_proof_out_of_range_raises() -> None:
    tree = MerkleTree.build([b"a", b"b"])
    try:
        tree.inclusion_proof(5)
    except IndexError:
        pass
    else:
        raise AssertionError("expected IndexError")


@given(leaves=st.lists(st.binary(min_size=1, max_size=20), min_size=1, max_size=40))
def test_every_leaf_has_a_valid_inclusion_proof(leaves: list[bytes]) -> None:
    tree = MerkleTree.build(leaves)
    for i, leaf in enumerate(leaves):
        proof = tree.inclusion_proof(i)
        assert verify_inclusion(tree.root, tree.size, i, leaf, proof)


@given(leaves=st.lists(st.binary(min_size=1, max_size=20), min_size=1, max_size=1))
def test_build_is_deterministic(leaves: list[bytes]) -> None:
    assert MerkleTree.build(leaves).root == MerkleTree.build(list(leaves)).root
