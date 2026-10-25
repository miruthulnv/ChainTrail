import hashlib
import hmac
import time

from config import GENESIS_PREV_HASH, SECRET_KEY
from hashing import canonical_json, sha256_text
from merkle import calculate_merkle_root


# Calculate the SHA-256 hash of a block header.
# We strip out header_hash and signature so we hash only the data fields.
def calculate_header_hash(header):
    clean_header = {}
    for key in header:
        if key != "header_hash" and key != "signature":
            clean_header[key] = header[key]
    header_json = canonical_json(clean_header)
    return sha256_text(header_json)


# Produce an HMAC-SHA256 signature for a header hash using the secret key.
def sign_hash(header_hash):
    key_bytes = SECRET_KEY.encode("utf-8")
    msg_bytes = header_hash.encode("utf-8")
    return hmac.new(key_bytes, msg_bytes, hashlib.sha256).hexdigest()


# Build a new block containing a signed header and its batch of entries.
def create_block(height, prev_hash, entries):
    # Step 1: Collect entry hashes
    entry_hashes = []
    for entry in entries:
        entry_hashes.append(entry["entry_hash"])

    # Step 2: Compute Merkle root over all entry hashes
    merkle_root = calculate_merkle_root(entry_hashes)

    # Step 3: Determine sequence bounds
    if len(entries) > 0:
        first_seq = entries[0]["seq"]
        last_seq = entries[-1]["seq"]
    else:
        first_seq = 0
        last_seq = 0

    entry_count = len(entries)
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

    # Step 4: Assemble the header without hash and signature
    header = {
        "height": height,
        "prev_hash": prev_hash,
        "merkle_root": merkle_root,
        "first_seq": first_seq,
        "last_seq": last_seq,
        "entry_count": entry_count,
        "timestamp": timestamp,
    }

    # Step 5: Hash and sign the header
    header_hash = calculate_header_hash(header)
    signature = sign_hash(header_hash)

    header["header_hash"] = header_hash
    header["signature"] = signature

    return {
        "header": header,
        "entries": entries,
    }


# Create the initial genesis block (height 0) with no entries.
def create_genesis_block():
    return create_block(0, GENESIS_PREV_HASH, [])
