"""Additive Signet vectors copied unchanged from nsec-tree/test/fixtures."""
import json
from pathlib import Path
from nsec_tree import derive, from_nsec, zeroise


def test_vault_vectors():
    fixture = json.loads((Path(__file__).parent / "fixtures/signet-vault-v1.json").read_text())
    root = from_nsec(bytes.fromhex(fixture["masterSecretHex"]))
    try:
        for vector in fixture["vectors"]:
            child = derive(root, vector["purpose"], vector["index"])
            try:
                assert child.private_key.hex() == vector["privateKeyHex"]
                assert child.public_key.hex() == vector["publicKeyHex"]
                assert child.index == vector["index"]
            finally:
                zeroise(child)
    finally:
        root.destroy()
