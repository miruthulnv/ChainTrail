import json
import os
import shutil

from config import BLOCKS_FILE, CHECKPOINT_FILE, DATA_FOLDER
from hashing import canonical_json

# Note on storage safety:
# We never open the blocks file in write mode, so old blocks are never overwritten by our code.
# The only legitimate operation on the log file is appending new blocks at the end.


# Create the data directory if it does not already exist.
def make_data_folder():
    if not os.path.exists(DATA_FOLDER):
        os.makedirs(DATA_FOLDER)


# Append a single block to the blocks log file.
# Always opened in "a" (append) mode so previous blocks are never overwritten.
def append_block(block):
    make_data_folder()
    block_line = canonical_json(block)
    with open(BLOCKS_FILE, "a", encoding="utf-8") as file:
        file.write(block_line + "\n")


# Read all blocks from the log file line by line.
# Returns an empty list if the log file does not exist.
def load_all_blocks():
    if not os.path.exists(BLOCKS_FILE):
        return []

    blocks = []
    with open(BLOCKS_FILE, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()
            if line:
                block = json.loads(line)
                blocks.append(block)
    return blocks


# Save the latest block checkpoint to disk.
def save_checkpoint(height, header_hash):
    make_data_folder()
    checkpoint_data = {
        "height": height,
        "header_hash": header_hash,
    }
    with open(CHECKPOINT_FILE, "w", encoding="utf-8") as file:
        file.write(canonical_json(checkpoint_data) + "\n")


# Read the latest checkpoint from disk.
# Returns None if the checkpoint file does not exist.
def load_checkpoint():
    if not os.path.exists(CHECKPOINT_FILE):
        return None

    with open(CHECKPOINT_FILE, "r", encoding="utf-8") as file:
        content = file.read().strip()
        if not content:
            return None
        return json.loads(content)


# Reset storage by removing the data directory and all stored files.
# Used by demos and tests to start with a fresh slate.
def reset_storage():
    if os.path.exists(DATA_FOLDER):
        shutil.rmtree(DATA_FOLDER)
