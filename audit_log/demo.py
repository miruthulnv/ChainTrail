import os
import shutil
import sys

from config import BLOCKS_FILE, CHECKPOINT_FILE
from logger import AuditLogger
from storage import load_all_blocks, reset_storage
import tamper
from verifier import print_verification_result, verify_log


# Print a concise summary row for each block in the audit log.
def display_chain():
    for b in load_all_blocks():
        h = b["header"]
        ht = h["height"]
        ent = "genesis" if ht == 0 else f"{h['first_seq']}-{h['last_seq']}"
        prev_8 = h["prev_hash"][:8] + "..."
        hash_8 = h["header_hash"][:8] + "..."
        merkle_8 = h["merkle_root"][:8] + "..."
        print(f"Block {ht} | entries: {ent:7s} | prev: {prev_8} | hash: {hash_8} | merkle: {merkle_8}")


# Run a single attack scenario, test verification, and restore clean files.
def test_attack(name, tamper_fn, blocks_bak, cp_bak):
    print(f"\n--- Attack: {name} ---")
    tamper_fn()
    problems = verify_log()
    print_verification_result(problems)
    shutil.copy(blocks_bak, BLOCKS_FILE)
    shutil.copy(cp_bak, CHECKPOINT_FILE)
    return "YES" if len(problems) > 0 else "NO"


# Attack functions
def attack_edit_entry():
    tamper.edit_entry(1, 0, "unauthorized_data.pdf")


def attack_edit_entry_and_fix_hash():
    tamper.edit_entry_and_fix_hash(1, 0, "unauthorized_data.pdf")


def attack_delete_block():
    tamper.delete_block(2)


def attack_swap_blocks():
    tamper.swap_blocks(1, 2)


def attack_truncate_tail():
    tamper.truncate_tail(1)


def attack_forge_block():
    tamper.forge_block(1)


# Allow user to pick an attack interactively
def run_interactive(attacks, blocks_bak, cp_bak):
    print("\nSelect an attack scenario to run:")
    for i in range(len(attacks)):
        print(f"  {i + 1}. {attacks[i][0]}")
    try:
        idx = int(input("\nEnter choice (1-6): ")) - 1
        if 0 <= idx < len(attacks):
            name, fn = attacks[idx]
            test_attack(name, fn, blocks_bak, cp_bak)
    except (ValueError, KeyboardInterrupt, EOFError):
        pass


# Main demo script executing the full audit log lifecycle.
def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)
    print("=======================================================")
    print("      Python Hash-Chained Audit Log Demo               ")
    print("=======================================================")

    print("\n[Step 1] Initializing clean audit log...")
    reset_storage()
    audit_logger = AuditLogger()

    print("\n[Step 2] Logging 10 sample events (Batch Size = 3)...")
    sample_events = [
        ("alice", "USER_LOGIN", "Console login from 192.168.1.10"),
        ("bob", "FILE_READ", "Read sensitive report.pdf"),
        ("carol", "CHANGE_PASSWORD", "Updated admin account password"),
        ("alice", "UPDATE_CONFIG", "Enabled two-factor authentication"),
        ("dave", "DATABASE_BACKUP", "Created snapshot db_backup.tar.gz"),
        ("bob", "DELETE_FILE", "Deleted temp export file temp.csv"),
        ("eve", "ROLE_ASSIGN", "Assigned auditor role to frank"),
        ("frank", "VIEW_AUDIT_LOG", "Audited security logs for Q3"),
        ("alice", "API_KEY_CREATE", "Generated read-only API key"),
        ("carol", "USER_LOGOUT", "Console session closed"),
    ]
    for actor, action, details in sample_events:
        entry = audit_logger.log_event(actor, action, details)
        print(f"  Log entry #{entry['seq']}: {actor} | {action} | {details}")

    audit_logger.flush()
    print("  Flushed unsealed entries to complete the chain.")

    print("\n[Step 3] Stored Block Chain:")
    display_chain()

    print("\n[Step 4] Verifying the clean audit log:")
    clean_problems = verify_log()
    print_verification_result(clean_problems)

    blocks_bak = BLOCKS_FILE + ".clean.bak"
    cp_bak = CHECKPOINT_FILE + ".clean.bak"
    shutil.copy(BLOCKS_FILE, blocks_bak)
    shutil.copy(CHECKPOINT_FILE, cp_bak)

    attack_list = [
        ("Edit entry", attack_edit_entry),
        ("Edit entry + fix entry hash", attack_edit_entry_and_fix_hash),
        ("Delete middle block", attack_delete_block),
        ("Swap two blocks", attack_swap_blocks),
        ("Truncate tail", attack_truncate_tail),
        ("Forge a block", attack_forge_block),
    ]

    if "--interactive" in sys.argv:
        run_interactive(attack_list, blocks_bak, cp_bak)
    else:
        print("\n[Step 5] Testing Tamper Resistance Scenarios...")
        results = []
        for name, fn in attack_list:
            results.append((name, test_attack(name, fn, blocks_bak, cp_bak)))

        print("\n" + "=" * 50)
        print(f"{'Attack':<35} {'Detected?':<10}")
        print("-" * 50)
        for attack_name, detected in results:
            print(f"{attack_name:<35} {detected:<10}")
        print("=" * 50)

    if os.path.exists(blocks_bak):
        os.remove(blocks_bak)
    if os.path.exists(cp_bak):
        os.remove(cp_bak)


if __name__ == "__main__":
    main()
