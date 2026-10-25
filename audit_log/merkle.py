from hashing import sha256_text


# Hash a leaf by prefixing with '00'.
# The '00' prefix distinguishes leaf nodes from interior nodes.
# This domain separation prevents second-preimage attacks where an attacker
# tries to pass off an internal node as an entry leaf.
def hash_leaf(entry_hash):
    return sha256_text("00" + entry_hash)


# Hash a pair of child nodes by prefixing with '01'.
# The '01' prefix marks interior tree nodes.
def hash_pair(left, right):
    return sha256_text("01" + left + right)


# Compute the Merkle root hash for a given list of entry hashes.
def calculate_merkle_root(entry_hashes):
    # Step 1: If the list is empty, return hash of 'empty'
    if len(entry_hashes) == 0:
        return sha256_text("empty")

    # Step 2: Turn every entry hash into a leaf hash
    current_level = []
    for entry_hash in entry_hashes:
        current_level.append(hash_leaf(entry_hash))

    # Step 3: Repeatedly combine pairs until only one root hash remains
    while len(current_level) > 1:
        next_level = []
        i = 0
        while i < len(current_level):
            if i + 1 < len(current_level):
                # We have a pair: combine left and right
                combined = hash_pair(current_level[i], current_level[i + 1])
                next_level.append(combined)
                i = i + 2
            else:
                # Odd hash out: carry it up to the next level unchanged
                next_level.append(current_level[i])
                i = i + 1
        current_level = next_level

    # Step 4: Return the final remaining root hash
    return current_level[0]
