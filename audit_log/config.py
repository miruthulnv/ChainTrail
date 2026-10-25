# Configuration constants for the audit log

BATCH_SIZE = 3                      # seal a block every 3 entries
DATA_FOLDER = "data"
BLOCKS_FILE = "data/blocks.jsonl"
CHECKPOINT_FILE = "data/checkpoint.json"
SECRET_KEY = "demo-secret-key"      # demo only, never hardcode in real systems
GENESIS_PREV_HASH = "0" * 64
