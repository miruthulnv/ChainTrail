# Simple Python Hash-Chained Audit Log

## 1. What This Project Is

This project is a lightweight, tamper-evident audit log implemented entirely in pure Python using only standard library modules. Events are collected into batches, sealed into block headers that cryptographically link to previous headers using SHA-256 hashes, and anchored with Merkle trees and HMAC signatures. A standalone verifier inspects the entire chain and detects any attempts to modify, reorder, delete, truncate, or forge log entries.

## 2. How to Run

Navigate into the `audit_log` directory:

```bash
cd audit_log
```

Run the automated attack and verification demo:
```bash
python demo.py
```

Run in interactive mode (choose which attack to run):
```bash
python demo.py --interactive
```

Inspect the stored blocks and events on disk:
```bash
python show_log.py
```

Run the unit test suite:
```bash
python test_audit_log.py
```

No external packages (`pip`) are required. Compatible with Python 3.8+.

## 3. How It Works

Audit events are appended sequentially. Instead of writing each event directly as an independent log line, events are grouped into batches of size 3 (configurable) and sealed into structured blocks:

1. **Individual Entries**: Each event is assigned an incrementing sequence number, a timestamp, actor, action, and details. A canonical SHA-256 hash (`entry_hash`) is computed over its fields.
2. **Merkle Trees**: The entry hashes within a batch are structured into a binary Merkle tree to compute a single `merkle_root`. This allows verifying batch integrity and supporting individual inclusion proofs.
3. **Block Headers**: A header is formed containing the block height, the previous block header's hash (`prev_hash`), the Merkle root, sequence boundaries (`first_seq`, `last_seq`), timestamp, and total entry count.
4. **HMAC Signature**: The header hash is signed using an HMAC-SHA256 key to prevent attackers without the key from fabricating blocks.
5. **Append-Only Disk Storage**: Blocks are written as JSON lines to `data/blocks.jsonl` exclusively using file append mode (`"a"`).
6. **External Checkpoint**: After each block is sealed, the latest block height and header hash are recorded to `data/checkpoint.json` to act as an external witness.

```text
 Entry1       Entry2       Entry3              Entry4       Entry5       Entry6
   |            |            |                   |            |            |
   +------- Merkle root -----+                   +------- Merkle root -----+
                |                                             |
   [Block 1: prev=GENESIS, root, hash]  --->  [Block 2: prev=hash of Block 1, ...]
```

## 4. Glossary

- **Hash (SHA-256)**: A one-way mathematical function that converts any text into a fixed 64-character hexadecimal fingerprint. Even changing a single character produces an unpredictable, completely different hash.
- **Merkle Root**: A single cryptographic hash representing an entire set of hashes arranged in a binary tree. If any leaf entry changes, the resulting Merkle root changes completely.
- **Block Header**: Metadata summarizing a batch of log entries, including block height, sequence boundaries, timestamp, Merkle root, previous block hash, and cryptographic signature.
- **Chain**: A sequence of blocks where each block explicitly includes the cryptographic hash of the previous block's header, forming an unbroken, tamper-evident link back to the genesis block.
- **Checkpoint**: A separate record of the latest block's height and header hash. It simulates an external witness (such as a public notary or transparency log) and prevents tail truncation attacks.
- **HMAC (Hash-based Message Authentication Code)**: A message authentication scheme that combines SHA-256 with a secret cryptographic key, ensuring that only holders of the key can produce valid block signatures.

## 5. File-by-File Guide

- `config.py`: Stores configuration constants including batch size, file paths, secret key, and genesis hash.
- `hashing.py`: Provides canonical JSON serialization and SHA-256 hashing helpers.
- `merkle.py`: Computes binary Merkle tree roots with domain separation prefixes (`00` for leaves, `01` for interior nodes).
- `block.py`: Handles creating, hashing, signing, and assembling block headers and genesis blocks.
- `storage.py`: Manages reading and append-only writing of blocks and checkpoints on disk.
- `logger.py`: Implements `AuditLogger` to buffer events, batch them, and seal blocks.
- `verifier.py`: Audits the chain from genesis to checkpoint and reports all detected discrepancies.
- `tamper.py`: Simulates malicious attacker actions (modifications, block deletion, reordering, tail truncation, forgery).
- `demo.py`: Runs a comprehensive demonstration showing normal operation followed by 6 attack and detection scenarios (supports `--interactive`).
- `test_audit_log.py`: Automated test suite covering hashing, Merkle trees, clean verification, sequence continuity, and attack detection.
- `inclusion_proof.py`: Generates and verifies cryptographic Merkle audit paths proving an entry exists in a block's root.
- `show_log.py`: Utility script that pretty-prints stored blocks, headers, and events from disk.

## 6. What the Verifier Checks

When `verify_log()` runs, it performs a strict multi-layer check across all blocks:

1. **Genesis Block Check**: Block 0 must have height 0 and `prev_hash` equal to the fixed genesis prev hash (`000...000`).
2. **Height Ordering**: Every block's height must match its 0-indexed position in the file (no skipped or duplicate heights).
3. **Previous Hash Linkage**: Block $N$'s `prev_hash` must exactly match Block $N-1$'s `header_hash`.
4. **Header Hash Integrity**: Recomputing the SHA-256 hash of the header's canonical JSON must match the stored `header_hash`.
5. **HMAC Signature Validity**: Recomputing the HMAC of the `header_hash` using the secret key must match the stored `signature`.
6. **Entry Count Consistency**: The stored `entry_count` must equal the exact number of entries in the block's list.
7. **Entry Hash Accuracy**: Recalculating the canonical SHA-256 hash of each entry must match its stored `entry_hash`.
8. **Merkle Root Verification**: Rebuilding the Merkle tree from all entry hashes must produce the exact `merkle_root` stored in the header.
9. **Sequence Continuity**: Sequence numbers must increase by 1 with no gaps across blocks (`first_seq == previous_last_seq + 1`).
10. **External Checkpoint Matching**: The height and header hash of the final block must match the values stored in `checkpoint.json`.

## 7. Demo Attacks and Detection

| Attack Scenario | Description | How It Is Caught |
|---|---|---|
| **Edit entry** | Attacker modifies an entry's `details` in-place | **Entry Hash Mismatch**: Recomputing the entry's hash fails against the stored `entry_hash`. |
| **Edit entry + fix hash** | Attacker alters `details` and recalculates the `entry_hash` | **Merkle Root Mismatch**: The entry hash is valid on its own, but combining it in the tree fails to match the header's `merkle_root`. |
| **Delete middle block** | Attacker removes Block 2 from disk | **Height & Linkage Broken**: Block 3 now occupies position 2 (height mismatch), its `prev_hash` does not match Block 1, and sequence numbers jump. |
| **Swap two blocks** | Attacker reorders Block 1 and Block 2 | **Linkage & Sequence Jump**: Heights do not match positions, `prev_hash` links fail, and entry sequence numbers are out of order. |
| **Truncate tail** | Attacker deletes the newest block(s) from the end | **Checkpoint Mismatch**: All remaining blocks are internally valid, but the external checkpoint still expects the truncated block height and hash. |
| **Forge a block** | Attacker modifies an entry and recalculates entry hash, Merkle root, and header hash | **Signature & Chain Mismatch**: Lacking the secret key, the attacker cannot forge a valid HMAC signature, and the subsequent block's `prev_hash` link is broken. |

## 8. Sample Output

Here is real output from running `python demo.py`:

```text
=======================================================
      Python Hash-Chained Audit Log Demo               
=======================================================

[Step 1] Initializing clean audit log...

[Step 2] Logging 10 sample events (Batch Size = 3)...
  Log entry #1: alice | USER_LOGIN | Console login from 192.168.1.10
  Log entry #2: bob | FILE_READ | Read sensitive report.pdf
  Log entry #3: carol | CHANGE_PASSWORD | Updated admin account password
  Log entry #4: alice | UPDATE_CONFIG | Enabled two-factor authentication
  Log entry #5: dave | DATABASE_BACKUP | Created snapshot db_backup.tar.gz
  Log entry #6: bob | DELETE_FILE | Deleted temp export file temp.csv
  Log entry #7: eve | ROLE_ASSIGN | Assigned auditor role to frank
  Log entry #8: frank | VIEW_AUDIT_LOG | Audited security logs for Q3
  Log entry #9: alice | API_KEY_CREATE | Generated read-only API key
  Log entry #10: carol | USER_LOGOUT | Console session closed
  Flushed unsealed entries to complete the chain.

[Step 3] Stored Block Chain:
Block 0 | entries: genesis | prev: 00000000... | hash: 3cafd300... | merkle: 2e1cfa82...
Block 1 | entries: 1-3     | prev: 3cafd300... | hash: 0f33f516... | merkle: 20941ca6...
Block 2 | entries: 4-6     | prev: 0f33f516... | hash: 94491718... | merkle: 46a0b31d...
Block 3 | entries: 7-9     | prev: 94491718... | hash: 305bb07c... | merkle: 34fa2bf0...
Block 4 | entries: 10-10   | prev: 305bb07c... | hash: 623bbcc0... | merkle: b62c2036...

[Step 4] Verifying the clean audit log:
[OK] Log is valid

[Step 5] Testing Tamper Resistance Scenarios...

--- Attack: Edit entry ---
[FAIL] Tampering or corruption detected:
  - Block 1: entry hash mismatch for seq 1

--- Attack: Edit entry + fix entry hash ---
[FAIL] Tampering or corruption detected:
  - Block 1: Merkle root mismatch

--- Attack: Delete middle block ---
[FAIL] Tampering or corruption detected:
  - Block 2: expected height 2, got 3
  - Block 2: prev_hash does not match previous block's header_hash
  - Block 3: first_seq mismatch (expected 4, got 7)
  - Block 3: expected height 3, got 4

--- Attack: Swap two blocks ---
[FAIL] Tampering or corruption detected:
  - Block 1: expected height 1, got 2
  - Block 1: prev_hash does not match previous block's header_hash
  - Block 2: first_seq mismatch (expected 1, got 4)
  - Block 2: expected height 2, got 1
  - Block 2: prev_hash does not match previous block's header_hash
  - Block 1: first_seq mismatch (expected 7, got 1)
  - Block 3: prev_hash does not match previous block's header_hash
  - Block 3: first_seq mismatch (expected 4, got 7)

--- Attack: Truncate tail ---
[FAIL] Tampering or corruption detected:
  - Log was truncated or rewritten (does not match checkpoint)

--- Attack: Forge a block ---
[FAIL] Tampering or corruption detected:
  - Block 1: signature mismatch
  - Block 2: prev_hash does not match previous block's header_hash

==================================================
Attack                              Detected? 
--------------------------------------------------
Edit entry                          YES       
Edit entry + fix entry hash         YES       
Delete middle block                 YES       
Swap two blocks                     YES       
Truncate tail                       YES       
Forge a block                       YES       
==================================================
```

## 9. Simplifications and What a Production System Would Add

This implementation prioritizes educational clarity using the Python standard library. A production-grade immutable audit system would add:

1. **Asymmetric Digital Signatures & KMS / HSM**:
   - *Current simplification*: Uses symmetric HMAC-SHA256 with a shared secret key. Anyone with the key can both create and verify blocks.
   - *Production*: Uses asymmetric cryptography (such as Ed25519 or ECDSA). Only the logging service holds the private key (stored in a Hardware Security Module or AWS KMS / Google Cloud KMS), while verifiers only need the public key.
2. **Independent Witnesses and External Timestamping**:
   - *Current simplification*: The checkpoint file is stored in the same local directory for demo convenience.
   - *Production*: Periodic checkpoints are published to an independent third-party witness network, a public blockchain, or a RFC 3161 cryptographic timestamping authority. This guarantees that tail truncation is provable even if the host filesystem is compromised.
3. **Crash Protection via Write-Ahead Log (WAL)**:
   - *Current simplification*: Entries buffered in `pending_entries` remain in memory until the batch size is reached or `flush()` is called. A power loss could drop unsealed events.
   - *Production*: Uses a durable append-only write-ahead log (WAL) on disk before buffering in memory.
4. **Replication and High Availability**:
   - *Current simplification*: Single-node filesystem writer.
   - *Production*: Raft or Paxos consensus across distributed log nodes with multi-region replication.
5. **Merkle Inclusion Proofs & Consistency Proofs**:
   - Enables lightweight clients to mathematically prove that a specific event exists in a block, or that an earlier log state is an exact prefix of the current log state, without downloading the entire database (similar to Certificate Transparency / RFC 6962). See `inclusion_proof.py` for a working implementation.
