# Script to pretty-print the audit log stored on disk.

from storage import load_all_blocks, load_checkpoint


# Display all blocks and their entries from the log file.
def show_log():
    blocks = load_all_blocks()
    if len(blocks) == 0:
        print("Audit log is empty.")
        return

    print("================================================================")
    print(f"               AUDIT LOG OVERVIEW ({len(blocks)} blocks)        ")
    print("================================================================")

    for block in blocks:
        header = block["header"]
        height = header["height"]
        print(f"\n[Block {height}]")
        print(f"  Timestamp   : {header['timestamp']}")
        print(f"  Prev Hash   : {header['prev_hash']}")
        print(f"  Merkle Root : {header['merkle_root']}")
        print(f"  Header Hash : {header['header_hash']}")
        print(f"  Signature   : {header['signature'][:16]}...")
        print(f"  Entries     : {header['entry_count']}")

        entries = block.get("entries", [])
        if len(entries) == 0:
            print("  (Genesis block - no entries)")
        else:
            for entry in entries:
                print(
                    f"    #{entry['seq']} [{entry['timestamp']}] "
                    f"{entry['actor']} -> {entry['action']} ({entry['details']})"
                )

    checkpoint = load_checkpoint()
    print("\n----------------------------------------------------------------")
    if checkpoint:
        print(
            f"Checkpoint -> Height: {checkpoint['height']}, "
            f"Hash: {checkpoint['header_hash'][:16]}..."
        )
    else:
        print("Checkpoint -> None")
    print("================================================================")


if __name__ == "__main__":
    show_log()
