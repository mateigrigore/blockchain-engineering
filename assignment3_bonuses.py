"""
Lab 3: Proof-of-Work blockchain over IPv8.

A single node implementation. Every group member runs almost the same file. Only one person registers
the group with the server, which happens with RegistrationCommunity.started (others have this commented out).
The code conceptually does the following:
    1. One node registers the group with the Registration community
    2. All nodes join the blockchain community.
    3. Then nodes start mining blocks, gossiping them to teammates, and converging on one chain via the 
    longest-chain rule (or most work done, in the case that the adaptive difficulty is used).
    4. The server sends transactions or other tests, to which we respond. The transactions are added to the mempool
    of the member that receives them, and then gossiped to teammates.

We use environment variables for global variables, so that the code can be run in 3 separate terminals with 
different ports and keys. For example:
    IPV8_PORT=8090 IPV8_KEY=../matei_key.pem python3 "assignment_3.py"
    IPV8_PORT=8091 IPV8_KEY=../halil_key.pem python3 "assignment_3.py"
    IPV8_PORT=8092 IPV8_KEY=../francesco_key.pem python3 "assignment_3.py"
"""

import asyncio
import hashlib
import os
from time import time

from ipv8.community import Community, CommunitySettings
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8.keyvault.crypto import default_eccrypto
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.payload import Payload
from ipv8.peer import Peer
from ipv8.peerdiscovery.network import PeerObserver
from ipv8.util import run_forever
from ipv8_service import IPv8

# ===== BONUS 3: Ledger Store =====
from src.bonus_assigs.bonus3_ledger_store import LedgerStore

# ===== BONUS 5: Adaptive Difficulty =====
from src.bonus_assigs.bonus5_adaptive_difficulty import (
    RetargetParams, next_difficulty, is_timestamp_acceptable,
    cumulative_work, median_timestamp,
)

# all nodes use the same group_id
GROUP_ID = os.environ.get("GROUP_ID", "dcffec1a6aabde90")

# Same 20-byte community ID for all nodes in the group
BLOCKCHAIN_COMMUNITY_ID = b"Lab3-Grp-Blockchain3"

# Community ID of the Registration overlay
REGISTRATION_COMMUNITY_ID = bytes.fromhex("4c616233426c6f636b636861696e323032365057")

# The public key of the server
SERVER_PUBLIC_KEY = bytes.fromhex(
    "4c69624e61434c504b3ae3fc099fb56ca3b5e1de9a1c843387f2acdbb78b1bd4350ffde518068a0d246"
    "344b10d0d8c355fd0d76873e7d7f7838f3715e025af08f791324495e083331ce6"
)

TXS_PER_BLOCK = 10 # the max number of txs pulled from the mempool
MINE_CHUNK = 20000 # number of nonces to try per task before yielding to the event loop
MINE_START_DELAY = 3.0 # time to wait for peers to be discovered before mining

# Directories for the base, the key, and the port number
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEY_PATH = os.environ.get("IPV8_KEY", os.path.join(BASE_DIR, "../keys", "my_peer_key.pem"))
PORT = int(os.environ.get("IPV8_PORT", "8090"))

# ===== BONUS 3: Ledger Store =====
# each local node needs its own on-disk store, so key the directory by port
# need to delete this directory to wipe a node's persisted chain and start clean
LEDGER_DIR = os.environ.get("LEDGER_DIR", os.path.join(BASE_DIR, f"ledger_{PORT}"))

# ===== BONUS 5: Adaptive Difficulty =====
# difficulty now adapts per block to hold a steady block time (which we define)
# all 3 nodes must share these parameters
# BOOTSTRAP_DIFFICULTY is the starting difficulty, where there is not enough history to measure block mining time
RETARGET_PARAMS = RetargetParams(
    target_interval=int(os.environ.get("TARGET_BLOCK_TIME", "10")), # how long each block should take to mine
    bootstrap_difficulty=int(os.environ.get("BOOTSTRAP_DIFFICULTY", "1")), # our starting difficulty (leading bits of 0)
) # can modify other class parameters here as we see fit, as found in bonus5_adaptive_difficulty.py

assert len(BLOCKCHAIN_COMMUNITY_ID) == 20, "BLOCKCHAIN_COMMUNITY_ID must be exactly 20 bytes"
assert len(REGISTRATION_COMMUNITY_ID) == 20, "REGISTRATION_COMMUNITY_ID must be exactly 20 bytes"

# Peer public keys
# H
PEER_H_PK = bytes.fromhex(
    "4c69624e61434c504b3aca9c493f737c67ecacba22f75974a176bb9e73f48f375d53536b8b4a082b4308e2ba9bad0af305536cba9a4c3de9352a10ed9e9afdddae3a95b8203133f3311a"
)

# F
PEER_F_PK = bytes.fromhex(
    "307e301006072a8648ce3d020106052b81040024036a0004015dfcc38f77c3f489f715f210d18fad35f315070282a1265b6994f4574b6c504bb592fbdf1a64f750ab3c8a5cfd125cc78b2fd40060835b78c17cb5f53d8e3626edc200630359a15acff13ce97eacf3e969b97fb62afbaee8f0d1495eddee367352e0e33d25d90d"
)

# M
PEER_M_PK = bytes.fromhex(
    "4c69624e61434c504b3a78b3a426b383064e29658b74b5e75816caf39d6fbc5c6aab11f22f91064a873857a14d2c997e1ff7387da6b2a69ee32bf70e379325eeeb2983492fd20c525735"
)

# ===========================================================================
# Hash / PoW helpers
# ===========================================================================
def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def count_leading_zeros(hash_int: int) -> int:
    """Leading zero bits of a 256-bit hash value (0 -> 256)."""
    return 256 - hash_int.bit_length()


def header_bytes(prev_hash: bytes, txs_hash: bytes, timestamp: int, difficulty: int, nonce: int) -> bytes:
    """84-byte block header in the exact spec order."""
    return (
        prev_hash # 32 bytes
        + txs_hash # 32 bytes
        + timestamp.to_bytes(8, "big") # uint64 BE
        + difficulty.to_bytes(4, "big") # uint32 BE
        + nonce.to_bytes(8, "big") # uint64 BE
    )


def tx_hash(sender_key: bytes, data: bytes, timestamp: int, signature: bytes) -> bytes:
    """32-byte hash of a transaction, used for the block's body commitment."""
    return sha256(sender_key + data + timestamp.to_bytes(8, "big") + signature)


def compute_txs_hash(tx_hashes: list) -> bytes:
    """Body commitment: SHA256 over concatenated tx hashes; SHA256(b'') if empty."""
    return sha256(b"".join(tx_hashes))


def short(b: bytes) -> str:
    """Returns the first 12 hex characters of a hash for easy reading in logging."""
    return b.hex()[:12]

# ===========================================================================
# Data model
# ===========================================================================
class Transaction:
    """
    This is the transaction data model, transactions received from the server are transformed to this format and stored
    in the mempool.
    """
    def __init__(self, sender_key: bytes, data: bytes, timestamp: int, signature: bytes, txh: bytes):
        self.sender_key = sender_key
        self.data = data
        self.timestamp = timestamp
        self.signature = signature
        self.tx_hash = txh


class Block:
    """
    This is the block data model. The chain is a list of these Block objects, and what is gossipped between nodes.
    """
    def __init__(self, height, prev_hash, txs_hash, block_hash, timestamp, difficulty, nonce):
        self.height = height
        self.prev_hash = prev_hash
        self.txs_hash = txs_hash
        self.block_hash = block_hash
        self.timestamp = timestamp
        self.difficulty = difficulty
        self.nonce = nonce
        self.txs = []         # full Transaction objects (only for blocks we mined)
        self.tx_hashes = []   # 32-byte hashes, always present


class Chain:
    # ===== BONUS 3: Ledger Store =====
    # the chain is no longer a python list in RAM; it is read through to an on-disk LedgerStore
    # blocks are stored as (header bytes, body bytes) and rebuilt into Block objects on demand
    # Hence reads stay O(1) and the chain survives restarts
    # only the mempool and the tip block live in memory
    def __init__(self, store_directory: str = LEDGER_DIR):
        self.store = LedgerStore(store_directory)
        self.mempool = {} # tx_hash -> Transaction
        # cache the tip block sto avoid a disk read.
        self._tip_block = None
        self._tip_height = self.store.height()
        # a fresh store has no blocks yet: write the shared genesis at height 0.
        if self._tip_height < 0:
            genesis = self._genesis()
            self._write_block(genesis)
            self._tip_block = genesis
            self._tip_height = 0
        else:
            self._tip_block = self._load_block(self._tip_height)
        # compact dead/superseded data in the background; never blocks writers.
        self.store.start_background_compaction(interval_seconds=30.0)

    @staticmethod
    def _genesis() -> Block:
        # Deterministic block 0 reproduced identically by every node
        # Only triggered when there is no locally persisted chain on disk
        # It is a synthetic block with no transactions, a zero prev_hash, and a zero txs_hash.
        prev = b"\x00" * 32
        txsh = sha256(b"")
        ts, diff, nonce = 0, 0, 0
        bh = sha256(header_bytes(prev, txsh, ts, diff, nonce))
        b = Block(0, prev, txsh, bh, ts, diff, nonce)
        b.txs, b.tx_hashes = [], []
        return b

    # ===== BONUS 3: Ledger Store =====
    # serialize a block into the (header, body) bytes the store keeps.
    @staticmethod
    def _block_to_bytes(block: Block):
        header = header_bytes(block.prev_hash, block.txs_hash, block.timestamp,
                              block.difficulty, block.nonce)
        body = b"".join(block.tx_hashes)
        return header, body

    # ===== BONUS 3: Ledger Store =====
    # write one block to the store at its own height.
    def _write_block(self, block: Block) -> None:
        header, body = self._block_to_bytes(block)
        self.store.put_block(block.height, header, body)

    # ===== BONUS 3: Ledger Store =====
    # rebuild a Block from the header + body stored at a height (None if absent).
    def _load_block(self, height: int):
        header = self.store.get_header(height)
        if header is None:
            return None
        prev_hash = header[0:32]
        txs_hash = header[32:64]
        timestamp = int.from_bytes(header[64:72], "big")
        difficulty = int.from_bytes(header[72:76], "big")
        nonce = int.from_bytes(header[76:84], "big")
        block_hash = sha256(header)
        block = Block(height, prev_hash, txs_hash, block_hash, timestamp, difficulty, nonce)
        body = self.store.get_body(height)
        block.tx_hashes = [body[i:i + 32] for i in range(0, len(body), 32)] if body else []
        block.txs = []
        return block

    # ===== BONUS 3: Ledger Store =====
    # return the block at a height, serving the cached tip without a disk read.
    def get_block(self, height: int) -> Block:
        if height == self._tip_height and self._tip_block is not None:
            return self._tip_block
        return self._load_block(height)

    # ===== BONUS 3: Ledger Store =====
    # number of blocks in the chain (genesis counts as one).
    def length(self) -> int:
        return self._tip_height + 1

    def tip(self) -> Block:
        # ===== BONUS 3: Ledger Store =====
        if self._tip_block is None:
            self._tip_block = self._load_block(self._tip_height)
        return self._tip_block

    def append_block(self, block: Block) -> None:
        # ===== BONUS 3: Ledger Store =====
        # persist the block (overwriting any block already at this height, which
        # is exactly what a tie-break tip swap needs) and move the tip cache.
        self._write_block(block)
        self._tip_block = block
        self._tip_height = block.height

    # ===== BONUS 3: Ledger Store =====
    # adopt a full candidate chain (from genesis) after a sync/reorg, writing
    # only the heights whose stored header actually differs.
    def adopt(self, blocks: list) -> None:
        for block in blocks[1:]:
            header, body = self._block_to_bytes(block)
            if self.store.get_header(block.height) != header:
                self.store.put_block(block.height, header, body)
        self._tip_block = blocks[-1]
        self._tip_height = blocks[-1].height

    # ===== BONUS 5: Adaptive Difficulty =====
    # the last `window+1` stored blocks below `height` (excluding genesis), as (timestamp, difficulty)
    # oldest-first, passed to next_difficulty() to calculate the next block's difficulty with median timestamp
    # and cumulative work.
    def recent_ancestors(self, height: int) -> list:
        start = max(1, height - (RETARGET_PARAMS.window + 1))
        result = []
        for h in range(start, height):
            block = self.get_block(h)
            if block is not None:
                result.append((block.timestamp, block.difficulty))
        return result

    def validate_block(self, block: Block, parent: Block, recent_ancestors=None) -> bool:
        """Validate a block against its parent: hash, PoW, link, body commitment.

        Checks four things every block must satisfy (header, proof-of-work,
        parent link, body commitment) and, when ancestors are supplied, two more
        that the adaptive-difficulty rule adds (declared difficulty + timestamp).

        NO transaction signature checks here: Blocks travel
        between peers carrying only tx_hashes, never the full transactions, so the
        raw data a signature check needs isn't available at this point.
        Signatures are verified only once, when a tx is admitted (SubmitTx / TxGossip).
        """
        if block.block_hash != sha256(header_bytes(
                block.prev_hash, block.txs_hash, block.timestamp, block.difficulty, block.nonce)):
            return False
        if count_leading_zeros(int.from_bytes(block.block_hash, "big")) < block.difficulty:
            return False
        if block.prev_hash != parent.block_hash:
            return False
        if compute_txs_hash(block.tx_hashes) != block.txs_hash:
            return False
        # ===== BONUS 5: Adaptive Difficulty =====
        # when the caller passes the block's ancestors, enforce that its declared
        # difficulty matches the retarget rule and its timestamp clears the median.
        if recent_ancestors is not None:
            if block.difficulty != next_difficulty(recent_ancestors, RETARGET_PARAMS):
                return False
            ancestor_timestamps = [ts for ts, _ in recent_ancestors]
            if not is_timestamp_acceptable(block.timestamp, ancestor_timestamps, RETARGET_PARAMS):
                return False
        return True


# ===========================================================================
# Payloads: For messages sent to/from the server and between peers
# ===========================================================================

# ---- Registration overlay ----
class RegisterBlockchain(Payload):
    msg_id = 1
    format_list = ["varlenHutf8", "varlenH"]

    def __init__(self, group_id: str, community_id: bytes):
        super().__init__()
        self.group_id = group_id
        self.community_id = community_id

    def to_pack_list(self):
        return [("varlenHutf8", self.group_id), ("varlenH", self.community_id)]

    @classmethod
    def from_unpack_list(cls, group_id, community_id):
        return cls(group_id, community_id)


class RegisterResponse(Payload):
    msg_id = 2
    format_list = ["?", "varlenHutf8"]

    def __init__(self, success: bool, message: str):
        super().__init__()
        self.success = success
        self.message = message

    def to_pack_list(self):
        return [("?", self.success), ("varlenHutf8", self.message)]

    @classmethod
    def from_unpack_list(cls, success, message):
        return cls(success, message)


# ---- Blockchain overlay: server-facing ----
class SubmitTx(Payload):
    msg_id = 1
    format_list = ["varlenH", "varlenH", "q", "varlenH"]

    def __init__(self, sender_key: bytes, data: bytes, timestamp: int, signature: bytes):
        super().__init__()
        self.sender_key = sender_key
        self.data = data
        self.timestamp = timestamp
        self.signature = signature

    def to_pack_list(self):
        return [("varlenH", self.sender_key), ("varlenH", self.data),
                ("q", self.timestamp), ("varlenH", self.signature)]

    @classmethod
    def from_unpack_list(cls, sender_key, data, timestamp, signature):
        return cls(sender_key, data, timestamp, signature)


class SubmitTxResponse(Payload):
    msg_id = 2
    format_list = ["?", "varlenH", "varlenHutf8"]

    def __init__(self, success: bool, tx_hash: bytes, message: str):
        super().__init__()
        self.success = success
        self.tx_hash = tx_hash
        self.message = message

    def to_pack_list(self):
        return [("?", self.success), ("varlenH", self.tx_hash), ("varlenHutf8", self.message)]

    @classmethod
    def from_unpack_list(cls, success, tx_hash, message):
        return cls(success, tx_hash, message)


class GetChainHeight(Payload):
    msg_id = 3
    format_list = ["q"]

    def __init__(self, request_id: int):
        super().__init__()
        self.request_id = request_id

    def to_pack_list(self):
        return [("q", self.request_id)]

    @classmethod
    def from_unpack_list(cls, request_id):
        return cls(request_id)


class ChainHeightResponse(Payload):
    msg_id = 4
    format_list = ["q", "q", "varlenH"]

    def __init__(self, request_id: int, height: int, tip_hash: bytes):
        super().__init__()
        self.request_id = request_id
        self.height = height
        self.tip_hash = tip_hash

    def to_pack_list(self):
        return [("q", self.request_id), ("q", self.height), ("varlenH", self.tip_hash)]

    @classmethod
    def from_unpack_list(cls, request_id, height, tip_hash):
        return cls(request_id, height, tip_hash)


class GetBlock(Payload):
    msg_id = 5
    format_list = ["q"]

    def __init__(self, height: int):
        super().__init__()
        self.height = height

    def to_pack_list(self):
        return [("q", self.height)]

    @classmethod
    def from_unpack_list(cls, height):
        return cls(height)


# 8 block fields shared by BlockResponse / NewBlock / ChainBlock.
_BLOCK_FORMAT = ["q", "varlenH", "varlenH", "q", "q", "q", "varlenH", "varlenH"]


class _BlockFields(Payload):
    """Shared wire layout for every message that makes use of a full block."""
    format_list = _BLOCK_FORMAT

    def __init__(self, height, prev_hash, txs_hash, timestamp, difficulty, nonce, block_hash, tx_hashes):
        super().__init__()
        self.height = height
        self.prev_hash = prev_hash
        self.txs_hash = txs_hash
        self.timestamp = timestamp
        self.difficulty = difficulty
        self.nonce = nonce
        self.block_hash = block_hash
        self.tx_hashes = tx_hashes      # concatenated 32-byte hashes (b"" for empty block)

    def to_pack_list(self):
        return [("q", self.height), ("varlenH", self.prev_hash), ("varlenH", self.txs_hash),
                ("q", self.timestamp), ("q", self.difficulty), ("q", self.nonce),
                ("varlenH", self.block_hash), ("varlenH", self.tx_hashes)]

    @classmethod
    def from_unpack_list(cls, height, prev_hash, txs_hash, timestamp, difficulty, nonce, block_hash, tx_hashes):
        return cls(height, prev_hash, txs_hash, timestamp, difficulty, nonce, block_hash, tx_hashes)


class BlockResponse(_BlockFields): # server query reply
    msg_id = 6


class NewBlock(_BlockFields): # inter-peer block announcement
    msg_id = 7


class GetFullChain(Payload): # ask a peer for their whole chain
    msg_id = 8
    format_list = ["q"]

    def __init__(self, from_height: int):
        super().__init__()
        self.from_height = from_height

    def to_pack_list(self):
        return [("q", self.from_height)]

    @classmethod
    def from_unpack_list(cls, from_height):
        return cls(from_height)


class ChainBlock(_BlockFields): # one streamed block of a full-chain reply
    msg_id = 9


class TxGossip(Payload):
    """Relay a transaction to teammates so any node can include it.

    Reuses the SubmitTx shape, but as its own msg_id so it does not collide with
    the server's Submit Transaction (msg 1).
    """
    msg_id = 10
    format_list = ["varlenH", "varlenH", "q", "varlenH"]

    def __init__(self, sender_key, data, timestamp, signature):
        super().__init__()
        self.sender_key = sender_key # public key of the sender, used to verify the signature and to compute the tx_hash
        self.data = data # payload, signed with sender_key
        self.timestamp = timestamp # distinguishes transactions with the same sender_key and data, included in signing
        self.signature = signature # for signature verification

    def to_pack_list(self):
        return [("varlenH", self.sender_key), ("varlenH", self.data),
                ("q", self.timestamp), ("varlenH", self.signature)]

    @classmethod
    def from_unpack_list(cls, sender_key, data, timestamp, signature):
        return cls(sender_key, data, timestamp, signature)


# ===========================================================================
# Registration overlay community
# ===========================================================================
class RegistrationCommunity(Community, PeerObserver):#
    """
    This community is used to register the group with the server.
    Only one node needs to do this, in the started() method.
    All nodes will discover the server and the teammates, but will not register.
    """
    community_id = REGISTRATION_COMMUNITY_ID

    def __init__(self, settings: CommunitySettings):
        super().__init__(settings)
        self.add_message_handler(RegisterResponse.msg_id, self.on_register_response)
        self.server_peer = None
        self.registered = False
        self.teammates = []

    def started(self):
        self.network.add_peer_observer(self)
        # self.register_task("reg_retry", self._try_register, interval=15.0, delay=5.0)
        # print(f"[reg] RegistrationCommunity started (group={GROUP_ID})")

    def on_peer_added(self, peer: Peer) -> None:
        if peer.public_key.key_to_bin() == PEER_F_PK:
            print("[reg] discovered peer F")
            self.teammates.append(peer)

        if peer.public_key.key_to_bin() == PEER_H_PK:
            print("[reg] discovered peer H")
            self.teammates.append(peer)

        if peer.public_key.key_to_bin() == SERVER_PUBLIC_KEY:
            self.server_peer = peer
            print("[reg] discovered Lab 3 server")

        if self.server_peer and len(self.teammates) == 2:
            print("[reg] ready to register with server")
            self._try_register()

    def on_peer_removed(self, peer: Peer) -> None:
        if self.server_peer and peer.public_key.key_to_bin() == SERVER_PUBLIC_KEY:
            self.server_peer = None

    def _try_register(self) -> None:
        """Send a RegisterBlockchain message to the server."""
        if self.registered or self.server_peer is None:
            return
        self.ez_send(self.server_peer, RegisterBlockchain(GROUP_ID, BLOCKCHAIN_COMMUNITY_ID))
        print(f"[reg] sent RegisterBlockchain community={short(BLOCKCHAIN_COMMUNITY_ID)}")

    @lazy_wrapper(RegisterResponse)
    def on_register_response(self, peer: Peer, payload: RegisterResponse) -> None:
        """Handle the server's reply to our registration attempt."""
        print(f"[reg] response success={payload.success} message={payload.message}")
        if payload.success:
            self.registered = True


# ===========================================================================
# Blockchain overlay community
# ===========================================================================
class BlockchainCommunity(Community, PeerObserver):
    community_id = BLOCKCHAIN_COMMUNITY_ID

    def __init__(self, settings: CommunitySettings):
        super().__init__(settings)
        self.add_message_handler(SubmitTx.msg_id, self.on_submit_tx)
        self.add_message_handler(GetChainHeight.msg_id, self.on_get_chain_height)
        self.add_message_handler(GetBlock.msg_id, self.on_get_block)
        self.add_message_handler(NewBlock.msg_id, self.on_new_block)
        self.add_message_handler(GetFullChain.msg_id, self.on_get_full_chain)
        self.add_message_handler(ChainBlock.msg_id, self.on_chain_block)
        self.add_message_handler(TxGossip.msg_id, self.on_tx_gossip)

        self.chain = Chain()
        self.seen_txs = {} # tx_hash -> Transaction (everything we ever accepted)
        self.sync_buffer = {} # height -> Block (incoming full-chain stream)
        self.mining_generation = 0 # bumped whenever the tip changes -> aborts in-flight mining
        self.teammates = []

    def started(self):
        """Start the community, register as a peer observer, and start mining in a background task."""
        self.network.add_peer_observer(self)
        self.register_anonymous_task("mine_loop", self._mine_loop)
        print(f"[chain] BlockchainCommunity started, genesis={short(self.chain.tip().block_hash)}")

    # ---- peer bookkeeping ----
    def on_peer_added(self, peer: Peer) -> None:
        if peer.public_key.key_to_bin() == PEER_F_PK:
            print("[chain comm] discovered peer F")
            self.teammates.append(peer)

        if peer.public_key.key_to_bin() == PEER_H_PK:
            print("[chain comm] discovered peer H")
            self.teammates.append(peer)

        if peer.public_key.key_to_bin() == SERVER_PUBLIC_KEY:
            print("[chain comm] discovered Lab 3 server")
            self.server = True

    def on_peer_removed(self, peer: Peer) -> None:
        if self.teammates and peer in self.teammates:
            self.teammates.remove(peer)
            print(f"[chain] peer left {short(peer.public_key.key_to_bin())}")

    def _teammates(self):
        """All peers in this overlay except the server."""
        return [p for p in self.get_peers() if p.public_key.key_to_bin() != SERVER_PUBLIC_KEY]

    def _broadcast(self, payload: Payload) -> None:
        """Send a payload to all teammates."""
        for p in self.teammates:
            self.ez_send(p, payload)

    @staticmethod
    def _block_payload(cls, block: Block):
        """Convert a Block to a payload of type cls (BlockResponse, NewBlock, or ChainBlock)."""
        return cls(block.height, block.prev_hash, block.txs_hash, block.timestamp,
                   block.difficulty, block.nonce, block.block_hash, b"".join(block.tx_hashes))

    @staticmethod
    def _block_from_payload(p) -> Block:
        """Convert a payload of type _BlockFields (BlockResponse, NewBlock, or ChainBlock) to a Block."""
        b = Block(p.height, p.prev_hash, p.txs_hash, p.block_hash, p.timestamp, p.difficulty, p.nonce)
        b.tx_hashes = [p.tx_hashes[i:i + 32] for i in range(0, len(p.tx_hashes), 32)]
        b.txs = []
        return b

    # ---- mempool helpers ----
    def _drop_included(self, block: Block) -> None:
        """Remove from the mempool any txs that were included in a block we just accepted."""
        for th in block.tx_hashes:
            self.chain.mempool.pop(th, None)

    def _rebuild_mempool(self) -> None:
        """After a reorg: drop txs already on-chain, re-add every other known tx."""
        # ===== BONUS 3: Ledger Store =====
        # walk the chain by height through the store rather than a python list.
        on_chain = set()
        for height in range(self.chain.length()):
            for th in self.chain.get_block(height).tx_hashes:
                on_chain.add(th)
        for th in list(self.chain.mempool.keys()):
            if th in on_chain:
                self.chain.mempool.pop(th, None)
        for th, tx in self.seen_txs.items():
            if th not in on_chain:
                self.chain.mempool[th] = tx

    # ---- signature verification ----
    @staticmethod
    def _valid_tx_signature(sender_key, data, timestamp, signature) -> bool:
        """Verify a transaction's signature using the sender's public key."""
        try:
            pub = default_eccrypto.key_from_public_bin(sender_key)
            signed = sender_key + data + timestamp.to_bytes(8, "big")
            return default_eccrypto.is_valid_signature(pub, signed, signature)
        except Exception as e:
            print(f"[chain] signature verify error: {e}")
            return False

    def _accept_tx(self, sender_key, data, timestamp, signature) -> bytes:
        """Verify + record a transaction. Returns its tx_hash, or None if invalid."""
        if not self._valid_tx_signature(sender_key, data, timestamp, signature):
            return None
        th = tx_hash(sender_key, data, timestamp, signature)
        # if seen, we will still send a success response to the server
        if th not in self.seen_txs:
            tx = Transaction(sender_key, data, timestamp, signature, th)
            # mark it as seen, add it to the mempool and share with others
            self.seen_txs[th] = tx
            self.chain.mempool[th] = tx
            self._broadcast(TxGossip(sender_key, data, timestamp, signature))
        return th

    # ===================== server query handlers =====================
    @lazy_wrapper(SubmitTx)
    def on_submit_tx(self, peer: Peer, payload: SubmitTx) -> None:
        """Handle a SubmitTx request from the server, verify the signature, and add to mempool if valid."""
        th = self._accept_tx(payload.sender_key, payload.data, payload.timestamp, payload.signature)
        if th is not None:
            print(f"[chain] tx accepted {short(th)} (mempool={len(self.chain.mempool)})")
            self.ez_send(peer, SubmitTxResponse(True, th, "accepted"))
        else:
            bad = tx_hash(payload.sender_key, payload.data, payload.timestamp, payload.signature)
            print(f"[chain] tx rejected (bad signature) {short(bad)}")
            self.ez_send(peer, SubmitTxResponse(False, bad, "invalid signature"))

    @lazy_wrapper(GetChainHeight)
    def on_get_chain_height(self, peer: Peer, payload: GetChainHeight) -> None:
        tip = self.chain.tip()
        print(f"[chain] GetChainHeight request_id={payload.request_id} -> h={tip.height} {short(tip.block_hash)}, from {short(peer.public_key.key_to_bin())}")
        self.ez_send(peer, ChainHeightResponse(payload.request_id, tip.height, tip.block_hash))

    @lazy_wrapper(GetBlock)
    def on_get_block(self, peer: Peer, payload: GetBlock) -> None:
        if 0 <= payload.height <= self.chain.tip().height:
            print(f"[chain] GetBlock h={payload.height} -> {short(self.chain.get_block(payload.height).block_hash)}, from {short(peer.public_key.key_to_bin())}")
            # ===== BONUS 3: Ledger Store =====
            self.ez_send(peer, self._block_payload(BlockResponse, self.chain.get_block(payload.height)))

    # ===================== gossip / consensus handlers =====================
    @lazy_wrapper(TxGossip)
    def on_tx_gossip(self, peer: Peer, payload: TxGossip) -> None:
        print(f"[recv] +tx gossip {short(tx_hash(payload.sender_key, payload.data, payload.timestamp, payload.signature))} from {short(peer.public_key.key_to_bin())}")
        self._accept_tx(payload.sender_key, payload.data, payload.timestamp, payload.signature)

    @lazy_wrapper(NewBlock)
    def on_new_block(self, peer: Peer, payload: NewBlock) -> None:
        """Handle a NewBlock announcement from a peer, validate it, and adopt it if it extends our tip or is a better fork."""
        block = self._block_from_payload(payload)
        tip = self.chain.tip()
        print(f"[recv] +block h={block.height} {short(block.block_hash)} from {short(peer.public_key.key_to_bin())}")

        if block.height == tip.height + 1 and block.prev_hash == tip.block_hash:
            # Directly extends our tip.
            # ===== BONUS 5: Adaptive Difficulty =====
            recent = self.chain.recent_ancestors(block.height)
            if self.chain.validate_block(block, tip, recent):
                self.chain.append_block(block)
                self.mining_generation += 1
                self._drop_included(block)
                print(f"[recv] +block h={block.height} {short(block.block_hash)} from {short(peer.public_key.key_to_bin())}")
                self._broadcast(self._block_payload(NewBlock, block))

        elif block.height >= tip.height + 1:
            # Higher than us but does not extend our tip -> their chain is longer.
            self._request_full_chain(peer)

        elif block.height == tip.height and block.block_hash != tip.block_hash \
                and block.prev_hash == tip.prev_hash:
            # Sibling at the tip: deterministic tie-break (smaller block_hash wins).
            self._maybe_swap_tip(block)

        elif block.height == tip.height and block.block_hash != tip.block_hash:
            # Deeper equal-height fork -> fetch and let the sync path decide by tie-break.
            self._request_full_chain(peer)
        # else: block is behind us (or a duplicate) -> ignore.

    def _maybe_swap_tip(self, block: Block) -> None:
        """"If the incoming block is a sibling of our tip, adopt it if its hash is smaller (deterministic tie-break)."""
        tip = self.chain.tip()
        if tip.height < 1:
            return
        # ===== BONUS 3: Ledger Store =====
        parent = self.chain.get_block(tip.height - 1)
        # ===== BONUS 5: Adaptive Difficulty =====
        recent = self.chain.recent_ancestors(block.height)
        if not self.chain.validate_block(block, parent, recent):
            return
        if int.from_bytes(block.block_hash, "big") < int.from_bytes(tip.block_hash, "big"):
            # ===== BONUS 3: Ledger Store =====
            # append_block overwrites the block stored at this height, so the
            # old tip is replaced atomically without a separate pop.
            self.chain.append_block(block)
            self.mining_generation += 1
            self._rebuild_mempool()
            print(f"[swap] tip h={block.height} -> {short(block.block_hash)}")
            self._broadcast(self._block_payload(NewBlock, block))

    def _request_full_chain(self, peer: Peer) -> None:
        self.ez_send(peer, GetFullChain(0))

    @lazy_wrapper(GetFullChain)
    def on_get_full_chain(self, peer: Peer, payload: GetFullChain) -> None:
        start = max(1, payload.from_height)           # genesis is shared, never streamed
        for h in range(start, self.chain.tip().height + 1):
            # ===== BONUS 3: Ledger Store =====
            self.ez_send(peer, self._block_payload(ChainBlock, self.chain.get_block(h)))

    @lazy_wrapper(ChainBlock)
    def on_chain_block(self, peer: Peer, payload: ChainBlock) -> None:
        print(f"[recv] +chain block h={payload.height} {short(payload.block_hash)} from {short(peer.public_key.key_to_bin())}")
        block = self._block_from_payload(payload)
        self.sync_buffer[block.height] = block
        self._try_adopt_synced_chain()

    def _try_adopt_synced_chain(self) -> None:
        """Assemble the best contiguous chain from genesis, preferring streamed
        blocks (sync buffer) but falling back to blocks we already hold, and adopt
        it if it is valid and strictly better (longer/more work, or equal length with a
        numerically smaller tip hash)."""
        # ===== BONUS 3: Ledger Store =====
        candidate = [self.chain.get_block(0)]         # our genesis (shared by all)
        h = 1
        while True:
            nxt = None
            # ===== BONUS 5: Adaptive Difficulty =====
            # ancestors for height h come from the candidate prefix, not the
            # stored chain, because on a competing fork they differ.
            recent = [(b.timestamp, b.difficulty)
                      for b in candidate[max(1, h - (RETARGET_PARAMS.window + 1)):]]
            buffered = self.sync_buffer.get(h)
            if buffered is not None and self.chain.validate_block(buffered, candidate[-1], recent):
                nxt = buffered
            # ===== BONUS 3: Ledger Store =====
            elif h < self.chain.length() and self.chain.validate_block(self.chain.get_block(h), candidate[-1], recent):
                nxt = self.chain.get_block(h)         # keep what we already have
            if nxt is None:
                break
            candidate.append(nxt)
            h += 1

        if len(candidate) <= 1:
            return

        # ===== BONUS 5: Adaptive Difficulty =====
        # with variable difficulty the better chain is the one with more total
        # work, not more blocks; ties still break on the smaller tip hash.
        current_tip_hash = self.chain.tip().block_hash
        candidate_work = cumulative_work([b.difficulty for b in candidate])
        current_work = cumulative_work(
            [self.chain.get_block(i).difficulty for i in range(self.chain.length())])
        better = (candidate_work > current_work) or (
            candidate_work == current_work
            and int.from_bytes(candidate[-1].block_hash, "big")
            < int.from_bytes(current_tip_hash, "big"))
        if not better:
            return

        # ===== BONUS 3: Ledger Store =====
        # persist the adopted chain (writes only the heights that differ).
        self.chain.adopt(candidate)
        self.mining_generation += 1
        self._rebuild_mempool()
        for k in [k for k in self.sync_buffer if k <= candidate[-1].height]:
            del self.sync_buffer[k]
        print(f"[sync] adopted chain len={len(candidate)} tip={short(candidate[-1].block_hash)}")
        self._broadcast(self._block_payload(NewBlock, candidate[-1]))

    # ===================== mining =====================
    def _build_candidate(self) -> Block:
        """Build a candidate block extending the current tip, including up to TXS_PER_BLOCK from the mempool."""
        tip = self.chain.tip()
        txs = list(self.chain.mempool.values())[:TXS_PER_BLOCK]
        tx_hashes = [t.tx_hash for t in txs]
        # ===== BONUS 5: Adaptive Difficulty =====
        # difficulty comes from the retarget rule over recent ancestors, and the
        # timestamp is forced above the median so our block clears peers' checks.
        recent = self.chain.recent_ancestors(tip.height + 1)
        difficulty = next_difficulty(recent, RETARGET_PARAMS)
        if difficulty != tip.difficulty:
            print(f"[diff] updating difficulty: {tip.difficulty} -> {difficulty} at height {tip.height + 1}")
        timestamp = int(time())
        ancestor_timestamps = [ts for ts, _ in recent]
        if ancestor_timestamps:
            floor = median_timestamp(ancestor_timestamps[-RETARGET_PARAMS.mtp_window:]) + 1
            timestamp = max(timestamp, floor)
        block = Block(tip.height + 1, tip.block_hash, compute_txs_hash(tx_hashes),
                      b"", timestamp, difficulty, 0)
        block.txs = txs
        block.tx_hashes = tx_hashes
        return block

    async def _search(self, block: Block, generation: int):
        """Cooperative PoW search: yields to the event loop every MINE_CHUNK hashes
        and aborts as soon as the tip changes (generation bumped)."""
        threshold = (1 << (256 - block.difficulty)) if block.difficulty < 256 else 0
        prefix = (block.prev_hash + block.txs_hash
                  + block.timestamp.to_bytes(8, "big") + block.difficulty.to_bytes(4, "big"))
        nonce = 0
        while nonce < (1 << 64):
            if generation != self.mining_generation:
                return None
            end = nonce + MINE_CHUNK
            while nonce < end:
                h = sha256(prefix + nonce.to_bytes(8, "big"))
                if int.from_bytes(h, "big") < threshold:
                    block.nonce = nonce
                    block.block_hash = h
                    return block
                nonce += 1
            await asyncio.sleep(0)
        return None

    async def _mine_loop(self) -> None:
        await asyncio.sleep(MINE_START_DELAY)
        while True:
            generation = self.mining_generation
            # build our candidate block
            candidate = self._build_candidate()
            # run the PoW search, yielding every MINE_CHUNK hashes and aborting if the tip changes (generation incremented)
            found = await self._search(candidate, generation)
            if found is not None and generation == self.mining_generation:
                self._accept_local_block(found)
            await asyncio.sleep(0)

    def _accept_local_block(self, block: Block) -> None:
        tip = self.chain.tip()
        if block.height != tip.height + 1 or block.prev_hash != tip.block_hash:
            return                                    # tip moved while we searched
        # ===== BONUS 5: Adaptive Difficulty =====
        recent = self.chain.recent_ancestors(block.height)
        # validate the block fully before accepting and broadcasting, even though we built it ourselves, to ensure
        # accidentally violating the difficulty or timestamp rules does not cause a fork
        # because the search only guarantees the hash and parent link are correct.
        if not self.chain.validate_block(block, tip, recent):
            return
        self.chain.append_block(block)
        self.mining_generation += 1
        # remove from the mempool
        self._drop_included(block)
        print(f"[mine] +block h={block.height} {short(block.block_hash)} txs={len(block.tx_hashes)}")
        # broadcast our new block!
        self._broadcast(self._block_payload(NewBlock, block))


# ===========================================================================
# Entry point
# ===========================================================================
async def start_client():
    if not os.path.exists(KEY_PATH):
        raise FileNotFoundError(KEY_PATH)

    # compress unsupported curve errors from other nodes
    install_unsupported_curve_filter()

    # set up IPv8
    builder = ConfigBuilder().clear_keys().clear_overlays()
    builder.add_key("my peer", "curve25519", KEY_PATH)
    builder.set_port(PORT)

    walker = [WalkerDefinition(Strategy.RandomWalk, 20, {"timeout": 3.0})]
    builder.add_overlay("RegistrationCommunity", "my peer", walker,
                        default_bootstrap_defs, {}, [("started",)])
    builder.add_overlay("BlockchainCommunity", "my peer", walker,
                        default_bootstrap_defs, {}, [("started",)])

    ipv8 = IPv8(builder.finalize(), extra_communities={
        "RegistrationCommunity": RegistrationCommunity,
        "BlockchainCommunity": BlockchainCommunity,
    })
    await ipv8.start()
    # ===== BONUS 5: Adaptive Difficulty =====
    print(f"Node up on UDP port {PORT}, key={os.path.basename(KEY_PATH)}, "
          f"bootstrap_difficulty={RETARGET_PARAMS.bootstrap_difficulty}, "
          f"target={RETARGET_PARAMS.target_interval}s, community={short(BLOCKCHAIN_COMMUNITY_ID)}")

    await run_forever()
    await ipv8.stop()


if __name__ == "__main__":
    asyncio.run(start_client())