"""ledger_store.py -- bonus #3: bounded, crash-safe storage for the Lab 3 chain.

standalone and stdlib-only. there is no IPv8 dependency here: every public method
takes and returns plain bytes/ints, so this module can be tested on its own and
imported into the node later without dragging the network in.

it has two layers:

    LogStructuredStore  a generic append-only bytes key/value store. it keeps an
                        in-memory index for O(1) reads, frames every record with a
                        checksum so a half-written record is dropped on restart,
                        splits data across segment files, and compacts old
                        segments in the background without blocking writers.

    LedgerStore         a thin wrapper that maps the chain onto that store: block
                        headers, block bodies, and account state each live under
                        their own key prefix. bodies can be pruned while headers
                        stay, so the chain is still verifiable from the headers.
"""

from __future__ import annotations

import json
import os
import struct
import threading
import zlib
from typing import Dict, List, Optional, Tuple

# every record on disk looks like this:
#   header  = magic(4) + payload_length(uint32 be) + checksum(uint32 be)   -> 12 bytes
#   payload = operation(1) + key_length(uint32 be) + key + value
# the checksum covers the payload only. a write that is cut off halfway leaves a
# short or checksum-failing frame at the very end of the active segment, which
# recovery detects and truncates away.
RECORD_MAGIC = b"LSS1"
HEADER_STRUCT = struct.Struct(">4sII")
HEADER_SIZE = HEADER_STRUCT.size

OPERATION_PUT = 0
OPERATION_DELETE = 1

# where a record lives: (segment_id, byte_offset_of_frame)
RecordLocation = Tuple[int, int]


def encode_record(operation: int, key: bytes, value: bytes) -> bytes:
    """turn one put/delete into the framed bytes we append to a segment file."""
    payload = bytes([operation]) + struct.pack(">I", len(key)) + key + value
    checksum = zlib.crc32(payload) & 0xFFFFFFFF
    return HEADER_STRUCT.pack(RECORD_MAGIC, len(payload), checksum) + payload


def decode_payload(payload: bytes) -> Tuple[int, bytes, bytes]:
    """split a payload back into (operation, key, value)."""
    operation = payload[0]
    key_length = struct.unpack(">I", payload[1:5])[0]
    key = payload[5 : 5 + key_length]
    value = payload[5 + key_length :]
    return operation, key, value


def scan_segment_file(path: str) -> Tuple[List[Tuple[int, bytes, int]], int]:
    """replay one segment front to back.

    returns (events, valid_size), where events is a list of
    (operation, key, frame_offset) and valid_size is the offset of the first
    torn/corrupt frame (i.e. where the file should be truncated). for an intact
    file valid_size equals the file size.
    """
    events: List[Tuple[int, bytes, int]] = []
    file_size = os.path.getsize(path)
    valid_size = 0
    with open(path, "rb") as handle:
        while valid_size + HEADER_SIZE <= file_size:
            header = handle.read(HEADER_SIZE)
            if len(header) < HEADER_SIZE:
                break
            magic, payload_length, checksum = HEADER_STRUCT.unpack(header)
            # anything that is not a clean, complete, checksum-matching frame is
            # treated as the torn tail and stops the scan.
            if magic != RECORD_MAGIC:
                break
            payload = handle.read(payload_length)
            if len(payload) != payload_length:
                break
            if (zlib.crc32(payload) & 0xFFFFFFFF) != checksum:
                break
            operation, key, _ = decode_payload(payload)
            events.append((operation, key, valid_size))
            valid_size += HEADER_SIZE + payload_length
    return events, valid_size


class Segment:
    """one append-only file. writes go to the end, reads seek anywhere."""

    def __init__(self, segment_id: int, path: str):
        self.segment_id = segment_id
        self.path = path
        # append mode forces every write to land at the end of the file.
        self.write_handle = open(path, "ab")
        self.read_handle = open(path, "rb")
        self.size = os.path.getsize(path)

    def append_record(self, record_bytes: bytes) -> int:
        """append a framed record and return the offset it was written at."""
        offset = self.size
        self.write_handle.write(record_bytes)
        # flush so the read handle can see the bytes immediately.
        self.write_handle.flush()
        self.size += len(record_bytes)
        return offset

    def flush_to_disk(self) -> None:
        """force buffered bytes out to the physical disk (durability)."""
        os.fsync(self.write_handle.fileno())

    def read_record(self, offset: int) -> Tuple[int, bytes, bytes]:
        """read and verify the framed record at a given offset."""
        self.read_handle.seek(offset)
        header = self.read_handle.read(HEADER_SIZE)
        magic, payload_length, checksum = HEADER_STRUCT.unpack(header)
        if magic != RECORD_MAGIC:
            raise ValueError("bad magic while reading record")
        payload = self.read_handle.read(payload_length)
        if len(payload) != payload_length or (zlib.crc32(payload) & 0xFFFFFFFF) != checksum:
            raise ValueError("corrupt or short record")
        return decode_payload(payload)

    def close(self) -> None:
        """close both file handles."""
        self.write_handle.close()
        self.read_handle.close()


class LogStructuredStore:
    """append-only bytes key/value store with O(1) reads and background compaction."""

    def __init__(
        self,
        directory: str,
        segment_max_bytes: int = 4 * 1024 * 1024,
        sync_on_write: bool = True,
    ):
        self.directory = directory
        self.segment_max_bytes = segment_max_bytes
        self.sync_on_write = sync_on_write
        os.makedirs(directory, exist_ok=True)

        self.lock = threading.RLock()
        # key -> (segment_id, frame_offset) of its latest live value.
        self.key_index: Dict[bytes, RecordLocation] = {}
        # segments in manifest order, oldest data first.
        self.segments: List[Segment] = []
        self.segment_by_id: Dict[int, Segment] = {}
        self.next_segment_id = 0

        self.stop_event = threading.Event()
        self.compaction_thread: Optional[threading.Thread] = None

        self._load_or_create()

    # ---- paths and manifest ----

    def _segment_path(self, segment_id: int) -> str:
        """on-disk path for a segment id."""
        return os.path.join(self.directory, f"seg-{segment_id:08d}.log")

    @property
    def manifest_path(self) -> str:
        """path of the file that lists the segment order."""
        return os.path.join(self.directory, "MANIFEST")

    def _save_manifest(self) -> None:
        """write the segment order atomically (temp file then rename)."""
        order = [segment.segment_id for segment in self.segments]
        temp_path = self.manifest_path + ".tmp"
        with open(temp_path, "w") as handle:
            json.dump({"segments": order, "next_id": self.next_segment_id}, handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, self.manifest_path)
        self._sync_directory()

    def _sync_directory(self) -> None:
        """fsync the directory so a rename survives a crash (best effort)."""
        try:
            directory_fd = os.open(self.directory, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError:
            # not all platforms allow fsync on a directory; ignore there.
            pass

    # ---- open and recover ----

    def _load_or_create(self) -> None:
        """rebuild the index from disk, or start a fresh store if empty."""
        segment_order: List[int] = []
        if os.path.exists(self.manifest_path):
            with open(self.manifest_path) as handle:
                manifest = json.load(handle)
            segment_order = manifest.get("segments", [])
            self.next_segment_id = manifest.get("next_id", 0)

        # brand new store: just open the first segment.
        if not segment_order:
            self._open_new_segment()
            return

        # replay every segment in order; later segments win, so the newest value
        # or tombstone for each key ends up in the index.
        for position, segment_id in enumerate(segment_order):
            path = self._segment_path(segment_id)
            events, valid_size = scan_segment_file(path)
            is_last_segment = position == len(segment_order) - 1
            # only the final segment can have a torn tail from an interrupted
            # write; truncate it back to the last good record.
            if valid_size < os.path.getsize(path) and is_last_segment:
                with open(path, "r+b") as handle:
                    handle.truncate(valid_size)

            segment = Segment(segment_id, path)
            self.segments.append(segment)
            self.segment_by_id[segment_id] = segment
            for operation, key, offset in events:
                if operation == OPERATION_PUT:
                    self.key_index[key] = (segment_id, offset)
                else:
                    self.key_index.pop(key, None)
            self.next_segment_id = max(self.next_segment_id, segment_id + 1)

    def _open_new_segment(self, save_manifest: bool = True) -> Segment:
        """start a new active segment and make it the place new writes go."""
        segment_id = self.next_segment_id
        self.next_segment_id += 1
        segment = Segment(segment_id, self._segment_path(segment_id))
        self.segments.append(segment)
        self.segment_by_id[segment_id] = segment
        if save_manifest:
            self._save_manifest()
        return segment

    # ---- writes ----

    def put(self, key: bytes, value: bytes) -> None:
        """store (or overwrite) the value for a key."""
        self._append(OPERATION_PUT, key, value)

    def delete(self, key: bytes) -> None:
        """mark a key as deleted by appending a tombstone."""
        self._append(OPERATION_DELETE, key, b"")

    def _append(self, operation: int, key: bytes, value: bytes) -> None:
        """append one framed record and update the in-memory index."""
        record_bytes = encode_record(operation, key, value)
        with self.lock:
            active_segment = self.segments[-1]
            # roll to a fresh segment once the active one is full.
            if active_segment.size and active_segment.size + len(record_bytes) > self.segment_max_bytes:
                active_segment = self._open_new_segment()
            offset = active_segment.append_record(record_bytes)
            if self.sync_on_write:
                active_segment.flush_to_disk()
            if operation == OPERATION_PUT:
                self.key_index[key] = (active_segment.segment_id, offset)
            else:
                self.key_index.pop(key, None)

    # ---- reads ----

    def get(self, key: bytes) -> Optional[bytes]:
        """return the latest value for a key, or None if missing or deleted."""
        with self.lock:
            location = self.key_index.get(key)
            if location is None:
                return None
            segment = self.segment_by_id[location[0]]
            offset = location[1]
        # the file read happens outside the index lookup; existing bytes never
        # move, so reading at a fixed offset is safe alongside appends.
        operation, _, value = segment.read_record(offset)
        return value if operation == OPERATION_PUT else None

    def keys_with_prefix(self, prefix: bytes = b"") -> List[bytes]:
        """list every live key that starts with the given prefix."""
        with self.lock:
            return [key for key in self.key_index if key.startswith(prefix)]

    # ---- compaction ----

    def compact(self) -> bool:
        """merge the sealed segments into one, dropping dead data.

        returns True if it did any work. writers are never blocked: we first roll
        a fresh active segment so the existing ones become immutable, copy only
        the latest live value of each key out of them into a temp file, rename it
        in atomically, then swap the manifest. writes during the copy land in the
        fresh segment and are left alone.
        """
        with self.lock:
            # nothing to do if the only segment is the active one.
            if len(self.segments) <= 1:
                return False
            self._open_new_segment(save_manifest=False)
            sealed_segments = self.segments[:-1]
            sealed_ids = {segment.segment_id for segment in sealed_segments}
            # snapshot the keys whose latest value currently lives in a sealed
            # segment; those are the ones worth copying forward.
            keys_to_copy = [
                (key, location)
                for key, location in self.key_index.items()
                if location[0] in sealed_ids
            ]

        # the heavy copy runs with no lock held, because sealed segments are
        # immutable from here on.
        compacted_id = self._reserve_segment_id()
        compacted_path = self._segment_path(compacted_id)
        temp_path = compacted_path + ".compacting"
        new_locations: Dict[bytes, RecordLocation] = {}
        with open(temp_path, "wb") as output:
            for key, location in keys_to_copy:
                source_segment = self.segment_by_id[location[0]]
                operation, stored_key, value = source_segment.read_record(location[1])
                if operation != OPERATION_PUT:
                    continue
                offset = output.tell()
                output.write(encode_record(OPERATION_PUT, stored_key, value))
                new_locations[key] = (compacted_id, offset)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temp_path, compacted_path)
        self._sync_directory()
        compacted_segment = Segment(compacted_id, compacted_path)

        # short lock to redirect the index and publish the new manifest.
        with self.lock:
            self.segment_by_id[compacted_id] = compacted_segment
            for key, new_location in new_locations.items():
                current = self.key_index.get(key)
                # only redirect if a newer write has not moved the key out of the
                # sealed segments in the meantime.
                if current is not None and current[0] in sealed_ids:
                    self.key_index[key] = new_location
            segments_after_roll = [s for s in self.segments if s.segment_id not in sealed_ids]
            # the compacted segment holds the oldest data, so it goes first.
            self.segments = [compacted_segment] + segments_after_roll
            self._save_manifest()
            for segment in sealed_segments:
                self.segment_by_id.pop(segment.segment_id, None)

        # reclaim the disk used by the old segments.
        for segment in sealed_segments:
            segment.close()
            try:
                os.remove(segment.path)
            except OSError:
                pass
        return True

    def _reserve_segment_id(self) -> int:
        """hand out the next segment id under the lock."""
        with self.lock:
            segment_id = self.next_segment_id
            self.next_segment_id += 1
            return segment_id

    def start_background_compaction(self, interval_seconds: float = 5.0) -> None:
        """run compaction on a daemon thread every interval_seconds."""
        if self.compaction_thread is not None:
            return
        self.stop_event.clear()

        def run_loop() -> None:
            while not self.stop_event.wait(interval_seconds):
                try:
                    self.compact()
                # a failure here must never kill the daemon thread.
                except Exception as error:
                    print(f"[store] background compaction error: {error}")

        self.compaction_thread = threading.Thread(
            target=run_loop, name="ledger-compaction", daemon=True
        )
        self.compaction_thread.start()

    def stop_background_compaction(self) -> None:
        """stop the background compaction thread if it is running."""
        self.stop_event.set()
        if self.compaction_thread is not None:
            self.compaction_thread.join(timeout=2.0)
            self.compaction_thread = None

    # ---- introspection and lifecycle ----

    def disk_bytes(self) -> int:
        """total bytes currently used by all segment files."""
        with self.lock:
            return sum(os.path.getsize(segment.path) for segment in self.segments)

    def live_key_count(self) -> int:
        """number of keys with a live value."""
        with self.lock:
            return len(self.key_index)

    def close(self) -> None:
        """stop compaction and close all files."""
        self.stop_background_compaction()
        with self.lock:
            for segment in self.segments:
                segment.close()


class LedgerStore:
    """blocks (header + body) and accounts on top of LogStructuredStore.

    key layout:
        b"H" + height(8 be)  ->  84-byte block header   (kept forever)
        b"B" + height(8 be)  ->  body blob, e.g. tx hashes  (prunable)
        b"A" + address       ->  account state bytes     (latest wins)
    """

    HEADER_PREFIX = b"H"
    BODY_PREFIX = b"B"
    ACCOUNT_PREFIX = b"A"

    def __init__(self, directory: str, **store_options):
        self.store = LogStructuredStore(directory, **store_options)
        # remember the highest block height we have a header for.
        self.tip_height = -1
        for key in self.store.keys_with_prefix(self.HEADER_PREFIX):
            height = int.from_bytes(key[1:9], "big")
            if height > self.tip_height:
                self.tip_height = height

    @staticmethod
    def _header_key(height: int) -> bytes:
        """key under which a block's header is stored."""
        return LedgerStore.HEADER_PREFIX + height.to_bytes(8, "big")

    @staticmethod
    def _body_key(height: int) -> bytes:
        """key under which a block's body is stored."""
        return LedgerStore.BODY_PREFIX + height.to_bytes(8, "big")

    # ---- blocks ----

    def put_block(self, height: int, header: bytes, body: bytes = b"") -> None:
        """store a block's header and (optionally) its body at a height."""
        self.store.put(self._header_key(height), header)
        if body:
            self.store.put(self._body_key(height), body)
        if height > self.tip_height:
            self.tip_height = height

    def get_header(self, height: int) -> Optional[bytes]:
        """return the header bytes at a height, or None."""
        return self.store.get(self._header_key(height))

    def get_body(self, height: int) -> Optional[bytes]:
        """return the body bytes at a height, or None (e.g. after pruning)."""
        return self.store.get(self._body_key(height))

    def height(self) -> int:
        """current tip height (-1 when empty)."""
        return self.tip_height

    def prune_bodies_below(self, keep_from_height: int) -> int:
        """drop block bodies below a height; headers stay so the chain is still
        verifiable. returns how many bodies were dropped."""
        dropped = 0
        for height in range(0, keep_from_height):
            if self.store.get(self._body_key(height)) is not None:
                self.store.delete(self._body_key(height))
                dropped += 1
        return dropped

    # ---- accounts ----

    def put_account(self, address: bytes, state: bytes) -> None:
        """store the latest state for an account."""
        self.store.put(self.ACCOUNT_PREFIX + address, state)

    def get_account(self, address: bytes) -> Optional[bytes]:
        """return an account's state, or None."""
        return self.store.get(self.ACCOUNT_PREFIX + address)

    # ---- passthrough to the underlying store ----

    def compact(self) -> bool:
        """run one compaction pass."""
        return self.store.compact()

    def start_background_compaction(self, interval_seconds: float = 5.0) -> None:
        """start compacting in the background."""
        self.store.start_background_compaction(interval_seconds)

    def disk_bytes(self) -> int:
        """total bytes on disk right now."""
        return self.store.disk_bytes()

    def close(self) -> None:
        """flush and close everything."""
        self.store.close()