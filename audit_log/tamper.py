# This file exists ONLY to simulate attacks on the audit log.
# In a real system, the audit logger code only appends new blocks.
# The functions here simulate an adversary with write access directly to the file system.

from block import calculate_header_hash
from config import BLOCKS_FILE
from hashing import canonical_json, hash_entry
from merkle import calculate_merkle_root
from storage import load_all_blocks


# Internal helper to overwrite the blocks file with tampered blocks.
def _rewrite_blocks_file(blocks):
    with open(BLOCKS_FILE, "w", encoding="utf-8") as file:
        for block in blocks:
            file.write(canonical_json(block) + "\n")


# Attack 1: Modify an entry's details, leaving its stored hash unchanged.
def edit_entry(block_index, entry_index, new_details):
    blocks = load_all_blocks()
    blocks[block_index]["entries"][entry_index]["details"] = new_details
    _rewrite_blocks_file(blocks)


# Attack 2: Modify entry details and update entry_hash to match.
# The entry check will pass, but the block Merkle root check will fail.
def edit_entry_and_fix_hash(block_index, entry_index, new_details):
    blocks = load_all_blocks()
    entry = blocks[block_index]["entries"][entry_index]
    entry["details"] = new_details
    entry["entry_hash"] = hash_entry(entry)
    _rewrite_blocks_file(blocks)


# Attack 3: Remove an entire block from the chain.
def delete_block(block_index):
    blocks = load_all_blocks()
    blocks.pop(block_index)
    _rewrite_blocks_file(blocks)


# Attack 4: Swap two blocks in the chain.
def swap_blocks(index_a, index_b):
    blocks = load_all_blocks()
    blocks[index_a], blocks[index_b] = blocks[index_b], blocks[index_a]
    _rewrite_blocks_file(blocks)


# Attack 5: Truncate the last N blocks from the tail of the log file.
# The blocks that remain are internally valid, but the external checkpoint catches it.
def truncate_tail(number_of_blocks):
    blocks = load_all_blocks()
    blocks = blocks[:-number_of_blocks]
    _rewrite_blocks_file(blocks)


# Attack 6: Modify an entry, fix entry_hash, Merkle root, and header_hash.
# The attacker lacks the secret key, so the HMAC signature check fails,
# and the next block's prev_hash linkage breaks.
def forge_block(block_index):
    blocks = load_all_blocks()
    block = blocks[block_index]

    # Modify an entry and recalculate its hash
    block["entries"][0]["details"] = "FORGED_DETAILS"
    block["entries"][0]["entry_hash"] = hash_entry(block["entries"][0])

    # Recalculate the Merkle root
    entry_hashes = []
    for entry in block["entries"]:
        entry_hashes.append(entry["entry_hash"])
    block["header"]["merkle_root"] = calculate_merkle_root(entry_hashes)

    # Recalculate header_hash (cannot forge signature without secret key)
    block["header"]["header_hash"] = calculate_header_hash(block["header"])

    _rewrite_blocks_file(blocks)
