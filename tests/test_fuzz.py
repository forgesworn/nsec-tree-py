"""Property/fuzz tests — parsers must only raise typed errors and round-trips must hold."""
from hypothesis import given, strategies as st
from nsec_tree import encoding
from nsec_tree.errors import NsecTreeError, InvalidKey
from nsec_tree.proof import proof_from_dict, verify_proof
from nsec_tree.event import from_event

SAFE = (NsecTreeError, InvalidKey, KeyError)  # KeyError = missing wire field, acceptable for dict input


@given(st.text())
def test_decode_nsec_never_crashes(s):
    try:
        encoding.decode_nsec(s)
    except Exception as e:  # noqa: BLE001
        assert isinstance(e, (NsecTreeError, InvalidKey)), repr(e)


@given(st.binary(min_size=32, max_size=32))
def test_encode_decode_nsec_roundtrip(b):
    assert encoding.decode_nsec(encoding.encode_nsec(b)) == b


@given(st.dictionaries(st.text(), st.text()))
def test_proof_from_dict_never_crashes_untyped(d):
    try:
        p = proof_from_dict(d)
        # verify_proof swallows all internal exceptions (returns bool), so only proof_from_dict can raise here
        verify_proof(p)
    except Exception as e:  # noqa: BLE001
        assert isinstance(e, SAFE), repr(e)


@given(pubkey=st.text(), tags=st.lists(st.lists(st.text(), min_size=1, max_size=3), max_size=8))
def test_from_event_only_typed_errors(pubkey, tags):
    try:
        from_event({"pubkey": pubkey, "tags": tags})
    except Exception as e:  # noqa: BLE001
        assert isinstance(e, NsecTreeError), repr(e)


@given(st.text())
def test_decode_npub_never_crashes(s):
    try:
        encoding.decode_npub(s)
    except Exception as e:  # noqa: BLE001
        assert isinstance(e, (NsecTreeError, InvalidKey)), repr(e)


@given(st.binary(min_size=32, max_size=32))
def test_encode_decode_npub_roundtrip(b):
    assert encoding.decode_npub(encoding.encode_npub(b)) == b
