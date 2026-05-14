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
from ipv8.util import run_forever
from ipv8.keyvault.crypto import default_eccrypto
from  ipv8.peerdiscovery.network import PeerObserver

# --- CONFIGURATION ---
EMAIL = "m.grigore@student.tudelft.nl"
GITHUB_URL = "https://github.com/mateigrigore/blockchain-engineering"
COMMUNITY_ID = bytes.fromhex("4c61623247726f75705369676e696e6732303236")
SERVER_PUBLIC_KEY = bytes.fromhex(
    "4c69624e61434c504b3a82e33614a342774e084af80835838d6dbdb64a537d3ddb6c1d82011a7f101553cda40cf5fa0e0fc23abd0a9c4f81322282c5b34566f6b8401f5f683031e60c96"
)
PEER1_PK = bytes.fromhex(
    "4c69624e61434c504b3aca9c493f737c67ecacba22f75974a176bb9e73f48f375d53536b8b4a082b4308e2ba9bad0af305536cba9a4c3de9352a10ed9e9afdddae3a95b8203133f3311a"
)

PEER2_PK = bytes.fromhex(
    "307e301006072a8648ce3d020106052b81040024036a0004015dfcc38f77c3f489f715f210d18fad35f315070282a1265b6994f4574b6c504bb592fbdf1a64f750ab3c8a5cfd125cc78b2fd40060835b78c17cb5f53d8e3626edc200630359a15acff13ce97eacf3e969b97fb62afbaee8f0d1495eddee367352e0e33d25d90d"
)

PEER_NAMES = {
    SERVER_PUBLIC_KEY: "Server",
    PEER1_PK: "Halil",
    PEER2_PK: "Francesco"
}

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEY_PATH = os.path.join(BASE_DIR, "..", "my_peer_key.pem")
# ---------------------

def sign_with_private_key(nonce: bytes):
    with open(KEY_PATH, "rb") as key_file:
        private_key = default_eccrypto.key_from_private_bin(key_file.read())
    
    return default_eccrypto.create_signature(private_key, nonce)


class RegisterPayload(Payload):
    msg_id = 1
    format_list = ["varlenH", "varlenH", "varlenH"]

    def __init__(self, member1_key: bytes, member2_key: bytes, member3_key: bytes):
        super().__init__()
        self.member1_key = member1_key
        self.member2_key = member2_key
        self.member3_key = member3_key

    def to_pack_list(self) -> list[tuple]:
        return [
            ("varlenH", self.member1_key),
            ("varlenH", self.member2_key),
            ("varlenH", self.member3_key),
        ]

    @classmethod
    def from_unpack_list(cls, member1_key: bytes, member2_key: bytes, member3_key: bytes):
        return cls(member1_key, member2_key, member3_key)


class RegisterResponsePayload(Payload):
    msg_id = 2
    format_list = ["?", "varlenHutf8", "varlenHutf8"]

    def __init__(self, success: bool, group_id: str, message: str):
        super().__init__()
        self.success = success
        self.group_id = group_id
        self.message = message

    def to_pack_list(self) -> list[tuple]:
        return [
            ("?", self.success),
            ("varlenHutf8", self.group_id),
            ("varlenHutf8", self.message),
        ]

    @classmethod
    def from_unpack_list(cls, success: bool, group_id: str, message: str):
        return cls(success, group_id, message)


class ChallengeRequest(Payload):
    msg_id = 3
    format_list = ["varlenHutf8"]

    def __init__(self, group_id: str):
        super().__init__()
        self.group_id = group_id

    def to_pack_list(self) -> list[tuple]:
        return [
            ("varlenHutf8", self.group_id),
        ]

    @classmethod
    def from_unpack_list(cls, group_id: str):
        return cls(group_id)


class ChallengeResponse(Payload):
    msg_id = 4
    format_list = ["varlenH", "q", "d"]

    def __init__(self, nonce: bytes, round_number: int, deadline: float):
        super().__init__()
        self.nonce = nonce
        self.round_number = round_number
        self.deadline = deadline

    def to_pack_list(self) -> list[tuple]:
        return [
            ("varlenH", self.nonce),
            ("q", self.round_number),
            ("d", self.deadline),
        ]

    @classmethod
    def from_unpack_list(cls, nonce: bytes, round_number: int, deadline: float):
        return cls(nonce, round_number, deadline)


class SignatureBundle(Payload):
    msg_id = 5
    format_list = ["varlenHutf8", "q", "varlenH", "varlenH", "varlenH"]

    def __init__(self, group_id: str, round_number: int, sig1: bytes, sig2: bytes, sig3: bytes):
        super().__init__()
        self.group_id = group_id
        self.round_number = round_number
        self.sig1 = sig1
        self.sig2 = sig2
        self.sig3 = sig3

    def to_pack_list(self) -> list[tuple]:
        return [
            ("varlenHutf8", self.group_id),
            ("q", self.round_number),
            ("varlenH", self.sig1),
            ("varlenH", self.sig2),
            ("varlenH", self.sig3),
        ]

    @classmethod
    def from_unpack_list(cls, group_id: str, round_number: int, sig1: bytes, sig2: bytes, sig3: bytes):
        return cls(group_id, round_number, sig1, sig2, sig3)


class RoundResultPayload(Payload):
    msg_id = 6
    format_list = ["?", "q", "q", "varlenHutf8"]

    def __init__(self, success: bool, round_number: int, rounds_completed: int, message: str):
        super().__init__()
        self.success = success
        self.round_number = round_number
        self.rounds_completed = rounds_completed
        self.message = message

    def to_pack_list(self) -> list[tuple]:
        return [
            ("?", self.success),
            ("q", self.round_number),
            ("q", self.rounds_completed),
            ("varlenHutf8", self.message),
        ]

    @classmethod
    def from_unpack_list(cls, success: bool, round_number: int, rounds_completed: int, message: str):
        return cls(success, round_number, rounds_completed, message)


class NoncePayload(Payload):
    msg_id = 7
    format_list = ["varlenH", "varlenHutf8"]

    def __init__(self, nonce: bytes, group_id: str):
        super().__init__()
        self.nonce = nonce
        self.group_id = group_id

    def to_pack_list(self) -> list[tuple]:
        return [
            ("varlenH", self.nonce),
            ("varlenHutf8", self.group_id),
        ]

    @classmethod
    def from_unpack_list(cls, nonce: bytes, group_id: str):
        return cls(nonce, group_id)


class SignedNoncePayload(Payload):
    msg_id = 8
    format_list = ["varlenH"]

    def __init__(self, signed_nonce: bytes):
        super().__init__()
        self.signed_nonce = signed_nonce

    def to_pack_list(self) -> list[tuple]:
        return [
            ("varlenH", self.signed_nonce),
        ]

    @classmethod
    def from_unpack_list(cls, signed_nonce: bytes):
        return cls(signed_nonce)

class RoundFinished(Payload):
    msg_id = 9
    format_list = ["q"]

    def __init__(self, round_number: int):
        super().__init__()
        self.round_number = round_number
    
    def to_pack_list(self) -> list[tuple]:
        return [
            ("q", self.round_number),
        ]

    @classmethod
    def from_unpack_list(cls, round_number: int):
        return cls(round_number)

class ReadyPayload(Payload):
    msg_id = 10
    format_list = ["?"]

    def __init__(self, ready: bool):
        super().__init__()
        self.ready = ready

    def to_pack_list(self) -> list[tuple]:
        return [
            ("?", self.ready)
        ]

    @classmethod
    def from_unpack_list(cls, ready: bool):
        return cls(ready)


class PoWCommunity(Community):
    community_id = COMMUNITY_ID

    def __init__(self, settings: CommunitySettings):
        super().__init__(settings)
        self.add_message_handler(4, self.on_challenge_response)
        self.add_message_handler(6, self.on_round_result)
        self.add_message_handler(7, self.on_receive_nonce)
        self.add_message_handler(8, self.on_receive_signed_nonce)
        self.add_message_handler(9, self.on_confirmation)
        self.server_peer: Peer | None = None
        self.peer1: Peer | None = None
        self.peer2: Peer | None = None
        self.sig1: bytes | None = None
        self.sig2: bytes | None = None
        self.my_sig: bytes | None = None
        self.group_id: str = None
        self.round: int = 0
        self.is_started: bool = False

    # def on_peer_added(self, peer: Peer) -> None:
    #     """Handle new peer discovery."""

    #     if self.is_started:
    #         return
        
    #     peer_key = peer.public_key.key_to_bin()
    #     if peer_key == SERVER_PUBLIC_KEY:
    #         print(f"Discovered server")
    #         self.server_peer = peer
    #         print(f"Is server peer set? {self.server_peer is not None}")

    #     elif peer_key == PEER1_PK:
    #         print(f"Discovered Peer 1")
    #         self.peer1 = peer
    #         self.online_members += 1
        

    #     elif peer_key == PEER2_PK:
    #         print(f"Discovered Peer 2")
    #         self.peer2 = peer
    #         self.online_members += 1
        
       

    #     if self.server_peer and self.peer1 and self.peer2:
    #         self.is_started = True
            
    #         print("All peers discovered.")
            
            

    #     if self.my_round == 1:
    #         self.register_group()
   

    # def on_peer_removed(self, peer: Peer) -> None:

    #     peer_key = peer.public_key.key_to_bin()

    #     if peer_key == SERVER_PUBLIC_KEY:
    #         print(f"Server disconnected")
    #         self.server_peer = peer

    #     elif peer_key == PEER1_PK:
    #         print(f"Peer 1 disconnected")
    #         self.peer1 = peer
    #         self.online_members -= 1
        
    #     elif peer_key == PEER2_PK:
    #         print(f"Peer 2 disconnected")
    #         self.peer2 = peer
    #         self.online_members -= 1

    #     # elif peer_key == PEER3_PK:
    #     #     print(f"Peer 3 disconnected")
    #     #     self.peer3 = peer
    #     #     self.online_members -= 1
        
    #     return

    def find_peer(self, public_key: bytes) -> Peer | None:
        """Find the server peer by matching its public key."""
        for peer in self.get_peers():
            if peer.public_key.key_to_bin() == public_key:

                if public_key == SERVER_PUBLIC_KEY:
                    self.server_peer = peer
                elif public_key == PEER1_PK:
                    self.peer1 = peer
                elif public_key == PEER2_PK:
                    self.peer2 = peer

                return peer
        return None
    
    def send_challenge_request(self, peer: Peer, group_id: str):
        self.ez_send(peer, ChallengeRequest(group_id))
        print(f"Sent challenge request to server for group {group_id}")

    def send_nonce(self, peer: Peer, nonce: bytes, group_id: str = ""):
        self.ez_send(peer, NoncePayload(nonce, group_id))
        print(f"Sent nonce to peer {PEER_NAMES.get(peer.public_key.key_to_bin(), peer.public_key.key_to_bin())}")

    def send_signed_nonce(self, peer: Peer, signed_nonce: bytes):
        self.ez_send(peer, SignedNoncePayload(signed_nonce))
        print(f"Sent signed nonce to peer {PEER_NAMES.get(peer.public_key.key_to_bin(), peer.public_key.key_to_bin())}")
    def send_submission(self, peer: Peer, group_id: str, round_number: int, sig1: bytes, sig2: bytes, sig3: bytes):
        self.ez_send(self.server_peer, SignatureBundle(group_id, round_number, sig1, sig2, sig3))
        print(f"Sent submission to peer {PEER_NAMES.get(peer.public_key.key_to_bin(), peer.public_key.key_to_bin())}")

    def send_confirmation(self, peer: Peer, round_number: int):
        self.ez_send(peer, RoundFinished(round_number))
        print(f"Sent confirmation to peer {PEER_NAMES.get(peer.public_key.key_to_bin(), peer.public_key.key_to_bin())}")

    @lazy_wrapper(ChallengeResponse)
    def on_challenge_response(self, peer: Peer, payload):
        if peer.public_key.key_to_bin() != SERVER_PUBLIC_KEY:
            print(f"Ignoring response from unknown peer")
            return

        print(f"Received challenge for round {payload.round_number} with deadline {payload.deadline}")

        self.my_sig = sign_with_private_key(payload.nonce)

        self.send_nonce(self.peer1, payload.nonce, self.group_id)
        self.send_nonce(self.peer2, payload.nonce, self.group_id)

    
    @lazy_wrapper(RoundResultPayload)
    def on_round_result(self, peer: Peer, payload):
        if peer.public_key.key_to_bin() != SERVER_PUBLIC_KEY:
            print(f"Ignoring response from unknown peer")
            return

        print(f"Round {payload.round_number} result: {'success' if payload.success else 'failure'} - {payload.message}")
        
        if payload.success:
            self.sig1 = None
            self.sig2 = None
            self.my_sig = None
            self.round += 1
            if payload.rounds_completed == 3:
                print(payload.message)
            else :
                #send confirmation to peers
                self.send_confirmation(self.peer1, payload.round_number)
                self.send_confirmation(self.peer2, payload.round_number)
                print(f"Sent confirmation for round {payload.round_number}")
    
    @lazy_wrapper(NoncePayload)
    def on_receive_nonce(self, peer: Peer, payload):
        if peer.public_key.key_to_bin() not in [PEER1_PK, PEER2_PK]:
            print(f"Ignoring response from unknown peer")
            return

        print(f"Received nonce from peer {PEER_NAMES.get(peer.public_key.key_to_bin(), peer.public_key.key_to_bin())} and sent signed nonce back")

        self.group_id = payload.group_id
        signed_nonce = sign_with_private_key(payload.nonce)
        
        self.send_signed_nonce(peer, signed_nonce)


    @lazy_wrapper(SignedNoncePayload)
    def on_receive_signed_nonce(self, peer: Peer, payload):
        if peer.public_key.key_to_bin() not in [PEER1_PK, PEER2_PK]:
            print(f"Ignoring response from unknown peer")
            return

        print(f"Received signed nonce from peer {PEER_NAMES.get(peer.public_key.key_to_bin(), peer.public_key.key_to_bin())}")

        if peer == self.peer1:
            self.sig1 = payload.signed_nonce
            if self.sig2 is not None:
                self.send_submission(self.server_peer, self.group_id, self.round, self.sig1, self.sig2, self.my_sig)
                print(f"Sent submission for round {self.round}")
        
        if peer == self.peer2:
            self.sig2 = payload.signed_nonce
            if self.sig1 is not None:
                self.send_submission(self.server_peer, self.group_id, self.round, self.sig1, self.sig2, self.my_sig)
                print(f"Sent submission for round {self.round}")


    @lazy_wrapper(RoundFinished)
    def on_confirmation(self, peer: Peer, payload):
        if peer.public_key.key_to_bin() not in [PEER1_PK, PEER2_PK]:
            print(f"Ignoring response from unknown peer")
            return

        self.round = payload.round_number + 1

        print(f"Received confirmation from peer {PEER_NAMES.get(peer.public_key.key_to_bin(), peer.public_key.key_to_bin())} for round {payload.round_number}")

        if self.round == 3:
            self.send_challenge_request(self.server_peer, self.group_id)

    def started(self) -> None:
        """Called when community is started."""
        self.network.add_peer_observer(self)
        print("Community started, waiting for peer discovery...")

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

    
    print("Waiting for server peer...")
    server = None
    while server is None:
        await asyncio.sleep(1.0)
        server = community.find_peer(SERVER_PUBLIC_KEY)
        community.server_peer = server
    print(f"Server found: {server}")

    print("Waiting for peer...")
    peer1 = None
    while peer1 is None:
        await asyncio.sleep(1.0)
        peer1 = community.find_peer(PEER1_PK)
        community.peer1 = peer1
    print(f"Server found: {peer1}")

    print("Waiting for peer...")
    peer2 = None
    while peer2 is None:
        await asyncio.sleep(1.0)
        peer2 = community.find_peer(PEER2_PK)
        community.peer2 = peer2
    print(f"Server found: {peer2}")

    community.ez_send(peer1, ReadyPayload(True))

    #First peer sends request

    # Wait for response
    # print("Waiting for server response...")
    # await asyncio.sleep(30)

    # await ipv8.stop()
    await run_forever()


if __name__ == "__main__":
    multiprocessing.freeze_support()
    asyncio.run(start_client())
