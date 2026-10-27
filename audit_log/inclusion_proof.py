# Merkle inclusion proof generator and verifier.
# Allows proving that an entry is part of a block without revealing all entries.

from hashing import hash_entry
from merkle import hash_leaf, hash_pair


# Generate an audit path (list of sibling hashes) proving an entry is in the block's Merkle root.
def generate_inclusion_proof(block, target_seq):
    entries = block.get("entries", [])
    target_index = -1
    for i in range(len(entries)):
        if entries[i].get("seq") == target_seq:
            target_index = i
            break

    if target_index == -1:
        return None

    # Build leaves
    current_level = []
    for entry in entries:
        current_level.append(hash_leaf(entry["entry_hash"]))

    proof = []
    current_idx = target_index

    while len(current_level) > 1:
        next_level = []
        i = 0
        while i < len(current_level):
            if i + 1 < len(current_level):
                # Pair of nodes
                left = current_level[i]
                right = current_level[i + 1]
                parent = hash_pair(left, right)
                next_level.append(parent)

                # Check if our current target is left or right in this pair
                if i == current_idx:
                    proof.append({"sibling": right, "position": "right"})
                elif i + 1 == current_idx:
                    proof.append({"sibling": left, "position": "left"})

                i = i + 2
            else:
                # Odd node carried up unchanged
                next_level.append(current_level[i])
                i = i + 1

        current_idx = current_idx // 2
        current_level = next_level

    return {
        "seq": target_seq,
        "entry": entries[target_index],
        "proof": proof,
        "merkle_root": block["header"]["merkle_root"],
    }


# Verify an inclusion proof against the block's Merkle root.
# Returns True if the entry mathematically hashes to the root, False otherwise.
def verify_inclusion_proof(entry, proof, expected_root):
    # Calculate the initial leaf hash
    current_hash = hash_leaf(hash_entry(entry))

    for step in proof:
        sibling = step["sibling"]
        position = step["position"]

        if position == "right":
            current_hash = hash_pair(current_hash, sibling)
        elif position == "left":
            current_hash = hash_pair(sibling, current_hash)
        else:
            return False

    return current_hash == expected_root
