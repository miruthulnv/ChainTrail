from block import calculate_header_hash, sign_hash
from config import GENESIS_PREV_HASH
from hashing import hash_entry
from merkle import calculate_merkle_root
from storage import load_all_blocks, load_checkpoint


# Verify the entire audit log on disk.
# Checks the chain of blocks, headers, hashes, signatures, Merkle roots,
# sequence numbers, and consistency with the external checkpoint.
# Returns a list of problem descriptions (empty list means all checks passed).
def verify_log():
    problems = []

    blocks = load_all_blocks()
    if len(blocks) == 0:
        problems.append("No blocks found in log")
        return problems

    last_seen_seq = 0

    # Inspect each block in sequence
    for i in range(len(blocks)):
        block = blocks[i]
        header = block.get("header", {})
        entries = block.get("entries", [])
        height = header.get("height")

        # Check 1: Block height must match its position in the list
        if height != i:
            problems.append(f"Block {i}: expected height {i}, got {height}")

        # Check 2: Genesis block or previous hash linkage
        if i == 0:
            if header.get("prev_hash") != GENESIS_PREV_HASH:
                problems.append("Block 0: prev_hash does not match genesis prev_hash")
        else:
            previous_block = blocks[i - 1]
            previous_header_hash = previous_block.get("header", {}).get("header_hash")
            if header.get("prev_hash") != previous_header_hash:
                problems.append(
                    f"Block {i}: prev_hash does not match previous block's header_hash"
                )

        # Check 3: Header hash recomputation
        computed_header_hash = calculate_header_hash(header)
        if computed_header_hash != header.get("header_hash"):
            problems.append(f"Block {height}: header hash mismatch")

        # Check 4: HMAC signature recomputation
        computed_signature = sign_hash(header.get("header_hash", ""))
        if computed_signature != header.get("signature"):
            problems.append(f"Block {height}: signature mismatch")

        # Check 5: Entry count must match entries list length
        if header.get("entry_count") != len(entries):
            problems.append(
                f"Block {height}: entry count mismatch (header: {header.get('entry_count')}, actual: {len(entries)})"
            )

        # Check 6: Each entry's hash must match its content
        entry_hashes = []
        for entry in entries:
            computed_entry_hash = hash_entry(entry)
            if computed_entry_hash != entry.get("entry_hash"):
                problems.append(
                    f"Block {height}: entry hash mismatch for seq {entry.get('seq')}"
                )
            entry_hashes.append(entry.get("entry_hash", ""))

        # Check 7: Merkle root recomputation
        computed_merkle_root = calculate_merkle_root(entry_hashes)
        if computed_merkle_root != header.get("merkle_root"):
            problems.append(f"Block {height}: Merkle root mismatch")

        # Check 8: Sequence numbers must continue without gaps
        if i == 0:
            if header.get("first_seq") != 0 or header.get("last_seq") != 0:
                problems.append("Block 0: genesis block sequence numbers must be 0")
            last_seen_seq = 0
        else:
            if len(entries) > 0:
                expected_first_seq = last_seen_seq + 1
                if header.get("first_seq") != expected_first_seq:
                    problems.append(
                        f"Block {height}: first_seq mismatch (expected {expected_first_seq}, got {header.get('first_seq')})"
                    )

                expected_last_seq = header.get("first_seq", 0) + len(entries) - 1
                if header.get("last_seq") != expected_last_seq:
                    problems.append(
                        f"Block {height}: last_seq mismatch (expected {expected_last_seq}, got {header.get('last_seq')})"
                    )

                # Verify individual entry sequences
                current_seq = header.get("first_seq", 0)
                for entry in entries:
                    if entry.get("seq") != current_seq:
                        problems.append(
                            f"Block {height}: entry sequence jump (expected {current_seq}, got {entry.get('seq')})"
                        )
                    current_seq = current_seq + 1

                last_seen_seq = header.get("last_seq", 0)

    # Check 9: External checkpoint check
    checkpoint = load_checkpoint()
    if checkpoint is None:
        problems.append("Log was truncated or rewritten (does not match checkpoint)")
    else:
        last_block = blocks[-1]
        last_height = last_block.get("header", {}).get("height")
        last_hash = last_block.get("header", {}).get("header_hash")
        if (
            last_height != checkpoint.get("height")
            or last_hash != checkpoint.get("header_hash")
        ):
            problems.append(
                "Log was truncated or rewritten (does not match checkpoint)"
            )

    return problems


# Helper function to print verification results nicely.
def print_verification_result(problems):
    if len(problems) == 0:
        print("[OK] Log is valid")
    else:
        print("[FAIL] Tampering or corruption detected:")
        for problem in problems:
            print("  - " + problem)
