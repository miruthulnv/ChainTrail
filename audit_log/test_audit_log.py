import os
import shutil

from config import BLOCKS_FILE, CHECKPOINT_FILE
from hashing import hash_entry, sha256_text
from inclusion_proof import generate_inclusion_proof, verify_inclusion_proof
from logger import AuditLogger
from merkle import calculate_merkle_root
from storage import load_all_blocks, reset_storage
import tamper
from verifier import verify_log


# Test that identical entries produce identical hashes and changes alter the hash.
def test_entry_hashing():
    e1 = {"seq": 1, "actor": "alice", "action": "LOGIN", "details": "ok"}
    e2 = {"seq": 1, "actor": "alice", "action": "LOGIN", "details": "ok"}
    e3 = {"seq": 1, "actor": "alice", "action": "LOGIN", "details": "failed"}
    assert hash_entry(e1) == hash_entry(e2)
    assert hash_entry(e1) != hash_entry(e3)


# Test Merkle root computation for 1, 2, 3, and 4 hashes and verify stability.
def test_merkle_roots():
    assert calculate_merkle_root([]) == sha256_text("empty")
    h1, h2, h3, h4 = (
        sha256_text("1"),
        sha256_text("2"),
        sha256_text("3"),
        sha256_text("4"),
    )
    r1, r2 = calculate_merkle_root([h1]), calculate_merkle_root([h1, h2])
    r3, r4 = (
        calculate_merkle_root([h1, h2, h3]),
        calculate_merkle_root([h1, h2, h3, h4]),
    )
    assert r1 == calculate_merkle_root([h1])
    assert r2 == calculate_merkle_root([h1, h2])
    assert r3 == calculate_merkle_root([h1, h2, h3])
    assert r4 == calculate_merkle_root([h1, h2, h3, h4])
    assert calculate_merkle_root([sha256_text("mod")]) != r1
    assert calculate_merkle_root([sha256_text("mod"), h2]) != r2
    assert calculate_merkle_root([h1, h2, sha256_text("mod")]) != r3
    assert calculate_merkle_root([h1, h2, h3, sha256_text("mod")]) != r4


# Test that a correctly generated log verifies with zero problems.
def test_clean_log():
    reset_storage()
    audit_logger = AuditLogger()
    for i in range(8):
        audit_logger.log_event("alice", f"OP_{i}", f"detail_{i}")
    audit_logger.flush()
    assert len(verify_log()) == 0
    reset_storage()


# Test sequence numbers are continuous across blocks with no gaps or overlaps.
def test_sequence_continuity():
    reset_storage()
    audit_logger = AuditLogger()
    for i in range(7):
        audit_logger.log_event("bob", "ACTION", f"entry_{i}")
    audit_logger.flush()
    blocks = load_all_blocks()
    assert len(blocks) == 4
    assert (
        blocks[0]["header"]["first_seq"] == 0
        and blocks[0]["header"]["last_seq"] == 0
    )
    expected_seq = 1
    for block in blocks[1:]:
        assert block["header"]["first_seq"] == expected_seq
        for entry in block["entries"]:
            assert entry["seq"] == expected_seq
            expected_seq = expected_seq + 1
        assert block["header"]["last_seq"] == expected_seq - 1
    reset_storage()


# Test that every tamper attack is detected by the verifier.
def test_all_tamper_attacks():
    reset_storage()
    audit_logger = AuditLogger()
    for i in range(10):
        audit_logger.log_event("carol", "EVENT", f"test_{i}")
    audit_logger.flush()
    blocks_bak, cp_bak = BLOCKS_FILE + ".bak", CHECKPOINT_FILE + ".bak"
    shutil.copy(BLOCKS_FILE, blocks_bak)
    shutil.copy(CHECKPOINT_FILE, cp_bak)

    def restore():
        shutil.copy(blocks_bak, BLOCKS_FILE)
        shutil.copy(cp_bak, CHECKPOINT_FILE)

    tamper.edit_entry(1, 0, "tampered_data")
    assert len(verify_log()) > 0
    restore()
    tamper.edit_entry_and_fix_hash(1, 0, "tampered_data")
    assert len(verify_log()) > 0
    restore()
    tamper.delete_block(2)
    assert len(verify_log()) > 0
    restore()
    tamper.swap_blocks(1, 2)
    assert len(verify_log()) > 0
    restore()
    tamper.truncate_tail(1)
    assert len(verify_log()) > 0
    restore()
    tamper.forge_block(1)
    assert len(verify_log()) > 0
    restore()
    if os.path.exists(blocks_bak):
        os.remove(blocks_bak)
    if os.path.exists(cp_bak):
        os.remove(cp_bak)
    reset_storage()


# Test Merkle inclusion proof generation and verification.
def test_inclusion_proofs():
    reset_storage()
    audit_logger = AuditLogger()
    for i in range(5):
        audit_logger.log_event("alice", "OP", f"data_{i}")
    audit_logger.flush()
    info = generate_inclusion_proof(load_all_blocks()[1], 2)
    assert (
        verify_inclusion_proof(info["entry"], info["proof"], info["merkle_root"])
        is True
    )
    bad = dict(info["entry"])
    bad["details"] = "tampered_data"
    assert verify_inclusion_proof(bad, info["proof"], info["merkle_root"]) is False
    reset_storage()


if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)
    test_entry_hashing()
    test_merkle_roots()
    test_clean_log()
    test_sequence_continuity()
    test_all_tamper_attacks()
    test_inclusion_proofs()
    print("All tests passed")
