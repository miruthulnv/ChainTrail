import hashlib
import json


# Convert a dictionary or list into a canonical JSON string.
# Sorting keys and using fixed separators ensures identical data always produces the same string.
def canonical_json(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


# Calculate the SHA-256 hex digest for any plain text string.
def sha256_text(text):
    text_bytes = text.encode("utf-8")
    return hashlib.sha256(text_bytes).hexdigest()


# Compute the SHA-256 hash of an entry before entry_hash is attached.
def hash_entry(entry):
    # Make a clean copy of the dictionary without entry_hash
    clean_entry = {}
    for key in entry:
        if key != "entry_hash":
            clean_entry[key] = entry[key]
    entry_json = canonical_json(clean_entry)
    return sha256_text(entry_json)
