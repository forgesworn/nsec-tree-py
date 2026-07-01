import pytest
from nsec_tree.validate import validate_purpose, validate_proof_purpose
from nsec_tree.errors import InvalidPurpose


def test_valid_purposes():
    for p in ["social", "commerce", "trott:rider", "402:api:v2:prod"]:
        validate_purpose(p)  # no raise


@pytest.mark.parametrize("bad", ["", "   ", "a\x00b", "x" * 256])
def test_invalid_purposes(bad):
    with pytest.raises(InvalidPurpose):
        validate_purpose(bad)


def test_255_bytes_ok_256_fails():
    validate_purpose("x" * 255)
    with pytest.raises(InvalidPurpose):
        validate_purpose("x" * 256)


def test_validate_proof_purpose_accepts_clean():
    validate_proof_purpose("social")  # no raise


@pytest.mark.parametrize("bad", ["a|b", "a\nb", "a\x7f"])
def test_validate_proof_purpose_rejects_unsafe(bad):
    with pytest.raises(InvalidPurpose):
        validate_proof_purpose(bad)
