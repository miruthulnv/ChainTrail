import time

from block import create_block, create_genesis_block
from config import BATCH_SIZE
from hashing import hash_entry
from storage import (
    append_block,
    load_all_blocks,
    make_data_folder,
    save_checkpoint,
)

# Note on pending entries:
# Entries waiting in self.pending_entries are held in memory and are not
# protected by block headers or hashes until sealed into a block.
# If the process crashes before seal_block() or flush() is called, unsealed
# entries in memory will be lost. In production, a write-ahead log (WAL) would be used.


class AuditLogger:
    # Initialize the audit logger, ensuring genesis block exists and reading current state.
    def __init__(self):
        make_data_folder()
        self.pending_entries = []

        existing_blocks = load_all_blocks()
        if len(existing_blocks) == 0:
            # Create and save genesis block
            genesis = create_genesis_block()
            append_block(genesis)
            save_checkpoint(
                genesis["header"]["height"],
                genesis["header"]["header_hash"],
            )
            self.current_height = 0
            self.last_hash = genesis["header"]["header_hash"]
            self.next_seq = 1
        else:
            # Resume from the last stored block
            last_block = existing_blocks[-1]
            self.current_height = last_block["header"]["height"]
            self.last_hash = last_block["header"]["header_hash"]
            if last_block["header"]["last_seq"] > 0:
                self.next_seq = last_block["header"]["last_seq"] + 1
            else:
                self.next_seq = 1

    # Record a new audit event, buffer it, and seal a block once batch size is reached.
    def log_event(self, actor, action, details):
        entry = {
            "seq": self.next_seq,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "actor": actor,
            "action": action,
            "details": details,
        }
        self.next_seq = self.next_seq + 1

        # Add the entry hash before appending
        entry["entry_hash"] = hash_entry(entry)
        self.pending_entries.append(entry)

        # Seal a block automatically if batch size is reached
        if len(self.pending_entries) >= BATCH_SIZE:
            self.seal_block()

        return entry

    # Seal all pending entries into a new block, append to disk, and update checkpoint.
    def seal_block(self):
        if len(self.pending_entries) == 0:
            return

        new_height = self.current_height + 1
        new_block = create_block(new_height, self.last_hash, self.pending_entries)

        append_block(new_block)
        save_checkpoint(
            new_block["header"]["height"],
            new_block["header"]["header_hash"],
        )

        self.last_hash = new_block["header"]["header_hash"]
        self.current_height = new_height
        self.pending_entries = []

    # Seal any remaining entries in memory so they are saved to disk.
    def flush(self):
        self.seal_block()
