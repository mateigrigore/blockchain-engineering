import asyncio
import hashlib
import multiprocessing
import os
import struct
import time

from ipv8.community import Community, CommunitySettings
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.payload import Payload
from ipv8.peer import Peer
from ipv8_service import IPv8

# --- CONFIGURATION ---
EMAIL = "m.grigore@student.tudelft.nl"
GITHUB_URL = "https://github.com/mateigrigore/blockchain-engineering"
COMMUNITY_ID = bytes.fromhex("2c1cc6e35ff484f99ebdfb6108477783c0102881")
SERVER_PUBLIC_KEY = bytes.fromhex(
    "4c69624e61434c504b3a86b23934a28d669c390e2d1fc0b0870706c4591cc0cb178bc5a811da6d87d27ef319b2638ef60cc8d119724f4c53a1ebfad919c3ac4136c501ce5c09364e0ebb"
)
DIFFICULTY_BITS = 28
# ---------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEY_PATH = os.path.join(BASE_DIR, "..", "my_peer_key.pem")

class SubmissionPayload(Payload):
    msg_id = 1
    format_list = ["varlenHutf8", "varlenHutf8", "q"]

    def __init__(self, email: str, github_url: str, nonce: int):
        super().__init__()
        self.email = email
        self.github_url = github_url
        self.nonce = nonce

    def to_pack_list(self) -> list[tuple]:
        """Tells IPv8 how to pack the variables into bytes."""
        return [
            ("varlenHutf8", self.email),
            ("varlenHutf8", self.github_url),
            ("q", self.nonce)
        ]

    @classmethod
    def from_unpack_list(cls, email: str, github_url: str, nonce: int):
        """Tells IPv8 how to recreate the object from received bytes."""
        return cls(email, github_url, nonce)


class ServerResponsePayload(Payload):
    msg_id = 2
    format_list = ["?", "varlenHutf8"]

    def __init__(self, success: bool, message: str):
        super().__init__()
        self.success = success
        self.message = message

    def to_pack_list(self) -> list[tuple]:
        return [
            ("?", self.success),
            ("varlenHutf8", self.message)
        ]

    @classmethod
    def from_unpack_list(cls, success: bool, message: str):
        return cls(success, message)


class PoWCommunity(Community):
    community_id = COMMUNITY_ID

    def __init__(self, settings: CommunitySettings):
        super().__init__(settings)
        self.add_message_handler(2, self.on_server_response)
        self.server_peer: Peer | None = None

    def find_server(self) -> Peer | None:
        """Find the server peer by matching its public key."""
        for peer in self.get_peers():
            if peer.public_key.key_to_bin() == SERVER_PUBLIC_KEY:
                self.server_peer = peer
                return peer
        return None

    def send_submission(self, peer: Peer, email: str, github_url: str, nonce: int):
        """Send a PoW submission message (message_id=1) to the server."""
        self.ez_send(peer, SubmissionPayload(email, github_url, nonce))

    @lazy_wrapper(ServerResponsePayload)
    def on_server_response(self, peer: Peer, payload):
        """Handle the server's response (message_id=2)."""
        if peer.public_key.key_to_bin() != SERVER_PUBLIC_KEY:
            print(f"Ignoring response from unknown peer")
            return
        status = "ACCEPTED" if payload.success else "REJECTED"
        print(f"[{status}] {payload.message}")


async def start_client():
    """Start the IPv8 client, mine a nonce, and submit it to the server."""

    if not os.path.exists(KEY_PATH):
        raise FileNotFoundError(KEY_PATH)

    builder = ConfigBuilder()
    builder.clear_keys()
    builder.add_key("my peer", "curve25519", KEY_PATH)
    builder.clear_overlays()
    builder.add_overlay(
        "PoWCommunity",
        "my peer",
        [WalkerDefinition(Strategy.RandomWalk, 20, {"timeout": 3.0})],
        default_bootstrap_defs,
        {},
        [],
    )

    ipv8 = IPv8(builder.finalize(), extra_communities={"PoWCommunity": PoWCommunity})
    await ipv8.start()

    community: PoWCommunity = ipv8.get_overlay(PoWCommunity)

    # Wait for server discovery
    print("Waiting for server peer...")
    server = None
    while server is None:
        await asyncio.sleep(1.0)
        server = community.find_server()
    print(f"Server found: {server}")

    nonce = 501002105

    # Send the submission
    print(f"Sending submission: email={EMAIL}, url={GITHUB_URL}, nonce={nonce}")
    community.send_submission(server, EMAIL, GITHUB_URL, nonce)

    # Wait for response
    print("Waiting for server response...")
    await asyncio.sleep(30)

    await ipv8.stop()


if __name__ == "__main__":
    multiprocessing.freeze_support()
    asyncio.run(start_client())
