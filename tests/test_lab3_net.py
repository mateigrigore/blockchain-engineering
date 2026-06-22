"""Offline convergence tests for the Lab 3 node, using py-ipv8's mock harness.

Run: python3 -m pytest tests/test_lab3_net.py

These exercise the consensus logic without real networking: block propagation,
fork tie-break, full-chain catch-up, and the full grading scenario (a tx is
accepted, buried >=3 deep, and all 3 nodes stay consistent at every height).
"""
import os
os.environ.setdefault("DIFFICULTY", "6")     # fast PoW for tests (must be set before import)

import importlib.util

HERE = os.path.dirname(os.path.abspath(__file__))
MODULE_PATH = os.path.join(HERE, "..", "assignment3.py")
_spec = importlib.util.spec_from_file_location("lab3_node", MODULE_PATH)
m = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(m)

from ipv8.test.base import TestBase
from ipv8.keyvault.crypto import default_eccrypto


class TestLab3(TestBase):
    def setUp(self):
        super().setUp()
        self.initialize(m.BlockchainCommunity, 3)

    # ---- helpers ----
    async def mine(self, idx, broadcast=True):
        node = self.overlay(idx)
        cand = node._build_candidate()
        found = await node._search(cand, node.mining_generation)
        if broadcast:
            node._accept_local_block(found)
        else:
            node.chain.append_block(found)
            node.mining_generation += 1
            node._drop_included(found)
        return found

    async def mine_sibling(self, idx, timestamp):
        """Mine a height-1 block with a chosen timestamp (to force distinct siblings)."""
        node = self.overlay(idx)
        tip = node.chain.tip()
        blk = m.Block(tip.height + 1, tip.block_hash, m.compute_txs_hash([]),
                      b"", timestamp, m.DIFFICULTY, 0)
        blk.tx_hashes = []
        found = await node._search(blk, node.mining_generation)
        node.chain.append_block(found)
        node.mining_generation += 1
        return found

    async def mine_n_local(self, idx, n, ts_base):
        """Mine n empty blocks onto node idx's own chain WITHOUT broadcasting, using
        explicit timestamps so two nodes build genuinely distinct (forked) chains."""
        node = self.overlay(idx)
        out = []
        for i in range(n):
            tip = node.chain.tip()
            blk = m.Block(tip.height + 1, tip.block_hash, m.compute_txs_hash([]),
                          b"", ts_base + i, m.DIFFICULTY, 0)
            blk.tx_hashes = []
            found = await node._search(blk, node.mining_generation)
            node.chain.append_block(found)
            node.mining_generation += 1
            out.append(found)
        return out

    def tips(self):
        return [self.overlay(i).chain.tip().block_hash for i in range(3)]

    def heights(self):
        return [self.overlay(i).chain.tip().height for i in range(3)]

    async def settle(self, rounds=6):
        for _ in range(rounds):
            await self.deliver_messages()

    # ---- tests ----
    async def test_linear_propagation(self):
        """Alternating miners with delivery each step: all converge, height grows."""
        for r in range(6):
            await self.mine(r % 3, broadcast=True)
            await self.settle(3)
        t = self.tips()
        self.assertEqual(t[0], t[1])
        self.assertEqual(t[1], t[2])
        self.assertEqual(self.heights(), [6, 6, 6])

    async def test_fork_tiebreak(self):
        """Two nodes mine competing height-1 blocks: all converge to smaller hash."""
        a = await self.mine_sibling(0, 1000)
        b = await self.mine_sibling(1, 2000)
        self.assertNotEqual(a.block_hash, b.block_hash)
        winner = a if int.from_bytes(a.block_hash, "big") < int.from_bytes(b.block_hash, "big") else b
        self.overlay(0)._broadcast(self.overlay(0)._block_payload(m.NewBlock, a))
        self.overlay(1)._broadcast(self.overlay(1)._block_payload(m.NewBlock, b))
        await self.settle(8)
        t = self.tips()
        self.assertEqual(t[0], t[1])
        self.assertEqual(t[1], t[2])
        self.assertEqual(t[0], winner.block_hash)
        self.assertEqual(self.heights(), [1, 1, 1])

    async def test_full_chain_catchup(self):
        """Node 0 silently builds a 4-block chain; a single announcement makes the
        other two fetch the full chain and adopt it."""
        n0 = self.overlay(0)
        for _ in range(4):
            await self.mine(0, broadcast=False)
        self.assertEqual(n0.chain.tip().height, 4)
        self.assertEqual(self.overlay(1).chain.tip().height, 0)
        n0._broadcast(n0._block_payload(m.NewBlock, n0.chain.tip()))
        await self.settle(10)
        t = self.tips()
        self.assertEqual(t[0], t[1])
        self.assertEqual(t[1], t[2])
        self.assertEqual(self.heights(), [4, 4, 4])

    async def test_transaction_buried_and_consistent(self):
        """A submitted tx propagates, lands in the chain, gets buried >=3 deep on
        every node, and all nodes agree on every block hash."""
        key = default_eccrypto.generate_key("curve25519")
        sender_key = key.pub().key_to_bin()
        data = b"lab3-test-transaction"
        ts = 1_718_000_000
        sig = default_eccrypto.create_signature(key, sender_key + data + ts.to_bytes(8, "big"))
        th = m.tx_hash(sender_key, data, ts, sig)

        # node 0 receives + gossips it
        accepted = self.overlay(0)._accept_tx(sender_key, data, ts, sig)
        self.assertEqual(accepted, th)
        await self.settle(4)
        for i in range(3):
            self.assertIn(th, self.overlay(i).seen_txs, f"node {i} missing tx in seen_txs")

        # mine until the tx is buried >= 3 deep, alternating miners
        for r in range(8):
            await self.mine(r % 3, broadcast=True)
            await self.settle(4)

        # consistency: identical block hash at every height on all nodes
        n0 = self.overlay(0)
        for i in (1, 2):
            ni = self.overlay(i)
            self.assertEqual(ni.chain.tip().height, n0.chain.tip().height)
            for h in range(n0.chain.tip().height + 1):
                self.assertEqual(ni.chain.blocks[h].block_hash, n0.chain.blocks[h].block_hash,
                                 f"mismatch at height {h} on node {i}")

        # tx is on-chain and buried >= 3 deep on every node
        for i in range(3):
            ni = self.overlay(i)
            tx_height = next((b.height for b in ni.chain.blocks if th in b.tx_hashes), None)
            self.assertIsNotNone(tx_height, f"tx not on-chain for node {i}")
            depth = ni.chain.tip().height - tx_height
            self.assertGreaterEqual(depth, 3, f"node {i}: tx only {depth} deep")

    async def test_diverged_peer_replaces_fork_clean(self):
        """A peer that mined its own private fork must DISCARD it and adopt a longer
        chain streamed by the network (no packet loss)."""
        n0, n1 = self.overlay(0), self.overlay(1)
        own = await self.mine_n_local(0, 5, ts_base=1_000)   # n0's private fork, height 5
        net = await self.mine_n_local(1, 8, ts_base=5_000)   # network chain, height 8
        self.assertEqual(n0.chain.tip().height, 5)
        self.assertNotEqual(own[0].block_hash, net[0].block_hash)   # genuinely forked at h=1

        # full, in-order stream of the network chain into n0's buffer
        for b in net:
            n0.sync_buffer[b.height] = b
        n0._try_adopt_synced_chain()

        self.assertEqual(n0.chain.tip().height, 8)
        self.assertEqual([blk.block_hash for blk in n0.chain.blocks[1:]],
                         [b.block_hash for b in net])
        own_hashes = {b.block_hash for b in own}
        for blk in n0.chain.blocks[1:]:
            self.assertNotIn(blk.block_hash, own_hashes, "own fork block survived the reorg")

    async def test_diverged_peer_recovers_after_dropped_fork_block(self):
        """Reproduces the reported bug: the fork-point ChainBlock is dropped in flight.

        The node must NOT silently keep its own losing fork (the old local-fallback
        poison). It must recognise the hole, request it, and adopt the full network
        chain once the missing block is (re)delivered."""
        n0, n1 = self.overlay(0), self.overlay(1)
        own = await self.mine_n_local(0, 5, ts_base=1_000)
        net = await self.mine_n_local(1, 8, ts_base=5_000)
        self.assertNotEqual(own[0].block_hash, net[0].block_hash)

        # stream the network chain but DROP the fork-point block (height 1)
        for b in net:
            if b.height == 1:
                continue
            n0.sync_buffer[b.height] = b
        n0._try_adopt_synced_chain()

        # must not strand itself: chain is still its own, uncorrupted...
        self.assertEqual(n0.chain.tip().height, 5)
        self.assertEqual([blk.block_hash for blk in n0.chain.blocks[1:]],
                         [b.block_hash for b in own])
        # ...and it must have asked for the missing height instead of papering over it
        self.assertIn(1, n0._awaiting, "node failed to request the dropped fork block")

        # the re-requested block now arrives -> full network chain gets adopted
        n0.sync_buffer[1] = net[0]
        n0._try_adopt_synced_chain()
        self.assertEqual(n0.chain.tip().height, 8)
        self.assertEqual([blk.block_hash for blk in n0.chain.blocks[1:]],
                         [b.block_hash for b in net])
        own_hashes = {b.block_hash for b in own}
        for blk in n0.chain.blocks[1:]:
            self.assertNotIn(blk.block_hash, own_hashes, "own fork block survived the reorg")
