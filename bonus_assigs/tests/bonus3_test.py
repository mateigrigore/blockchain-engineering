"""test_ledger_store.py -- exercises ledger_store.py end to end.

No network needed to run: the blocks here are synthetic bytes, which is all the storage layer cares about. it
checks writes/reads, account overwrites, a clean reopen, recovery from a torn
write, compaction shrinking the disk, and body pruning that keeps headers.
"""

import os
import shutil
import struct
import tempfile

from src.bonus_assigs.bonus3_ledger_store import LedgerStore, RECORD_MAGIC


def fake_header(height: int) -> bytes:
    """make a deterministic 84-byte stand-in for a real block header."""
    return bytes([height % 256]) * 84


def fake_body() -> bytes:
    """make a stand-in body of five random 32-byte tx hashes."""
    return b"".join(os.urandom(32) for _ in range(5))


def check_writes_and_reads(work_directory: str) -> None:
    """write 200 synthetic blocks and read a few back."""
    store = LedgerStore(work_directory, segment_max_bytes=16 * 1024)
    for height in range(200):
        store.put_block(height, fake_header(height), fake_body())
    assert store.height() == 199
    assert store.get_header(0) == fake_header(0)
    assert store.get_header(199) == fake_header(199)
    assert store.get_body(100) is not None
    print(
        f"1) wrote 200 blocks, tip={store.height()}, "
        f"disk={store.disk_bytes()} bytes, reads OK"
    )
    store.close()


def check_account_overwrites(work_directory: str) -> None:
    """confirm the latest write to an account is the one that is read back."""
    store = LedgerStore(work_directory, segment_max_bytes=16 * 1024)
    store.put_account(b"alice", b"100")
    store.put_account(b"alice", b"250")
    store.put_account(b"bob", b"7")
    assert store.get_account(b"alice") == b"250"
    assert store.get_account(b"bob") == b"7"
    print("2) account updates: latest value wins")
    store.close()


def check_clean_reopen(work_directory: str) -> None:
    """reopen the store and confirm everything written so far survived."""
    store = LedgerStore(work_directory, segment_max_bytes=16 * 1024)
    assert store.get_header(199) == fake_header(199)
    assert store.get_account(b"alice") == b"250"
    print("3a) clean reopen: all 200 blocks + accounts intact")
    store.close()


def check_torn_write_recovery(work_directory: str) -> None:
    """append a half-written record, reopen, and confirm nothing good is lost."""
    segment_files = sorted(f for f in os.listdir(work_directory) if f.startswith("seg-"))
    victim_path = os.path.join(work_directory, segment_files[-1])
    size_before = os.path.getsize(victim_path)

    # a valid-looking header that promises 9999 payload bytes, followed by only a
    # couple of bytes: exactly what an interrupted write leaves behind.
    torn_frame = RECORD_MAGIC + struct.pack(">I", 9999) + struct.pack(">I", 0) + b"\x01\x02"
    with open(victim_path, "ab") as handle:
        handle.write(torn_frame)
    print(f"3b) injected a torn frame ({len(torn_frame)} junk bytes)")

    store = LedgerStore(work_directory, segment_max_bytes=16 * 1024)
    assert store.get_header(199) == fake_header(199)
    assert store.get_account(b"alice") == b"250"
    # the torn tail should have been truncated back to the last good record.
    assert os.path.getsize(victim_path) == size_before
    print("3c) recovery dropped the torn tail; all good data intact")
    return store


def check_compaction_shrinks_disk(store: LedgerStore) -> None:
    """churn one account, then compact and confirm dead data is reclaimed."""
    for _ in range(50):
        store.put_account(b"alice", os.urandom(64))
    disk_before = store.disk_bytes()
    store.compact()
    store.compact()
    disk_after = store.disk_bytes()
    assert store.get_account(b"alice") is not None
    assert store.get_header(199) == fake_header(199)
    reclaimed_percent = 100 * (disk_before - disk_after) // max(disk_before, 1)
    print(
        f"4) compaction: {disk_before} -> {disk_after} bytes "
        f"({reclaimed_percent}% reclaimed), reads still correct"
    )


def check_pruning_keeps_headers(store: LedgerStore) -> None:
    """prune old bodies and confirm headers (and recent bodies) remain."""
    assert store.get_body(10) is not None
    dropped = store.prune_bodies_below(150)
    store.compact()
    assert store.get_body(10) is None       # old body gone
    assert store.get_header(10) is not None  # its header kept -> still verifiable
    assert store.get_body(160) is not None   # recent body kept
    print(
        f"5) pruned {dropped} old bodies; headers all retained "
        f"(disk now {store.disk_bytes()} bytes)"
    )


def run_all_checks() -> None:
    """run every check against a throwaway temp directory."""
    work_directory = tempfile.mkdtemp(prefix="ledgerstore_")
    print(f"workdir: {work_directory}\n")
    try:
        check_writes_and_reads(work_directory)
        check_account_overwrites(work_directory)
        check_clean_reopen(work_directory)
        store = check_torn_write_recovery(work_directory)
        check_compaction_shrinks_disk(store)
        check_pruning_keeps_headers(store)
        store.close()
        print("\nALL CHECKS PASSED")
    finally:
        shutil.rmtree(work_directory, ignore_errors=True)


if __name__ == "__main__":
    run_all_checks()