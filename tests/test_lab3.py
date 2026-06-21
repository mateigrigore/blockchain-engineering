"""Unit checks for the Lab 3 blockchain primitives.

Run directly:   python3 tests/test_lab3.py
Or with pytest: python3 -m pytest tests/test_lab3.py
"""
import importlib.util
import os

HERE = os.path.dirname(os.path.abspath(__file__))
MODULE_PATH = os.path.join(HERE, "..", "assignment_3 (1).py")


def _load():
    spec = importlib.util.spec_from_file_location("lab3_node", MODULE_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_primitives():
    m = _load()

    # 1. community ids are 20 bytes
    assert len(m.BLOCKCHAIN_COMMUNITY_ID) == 20
    assert len(m.REGISTRATION_COMMUNITY_ID) == 20

    # 2. genesis deterministic + self-consistent
    g1 = m.Chain._genesis()
    g2 = m.Chain._genesis()
    assert g1.block_hash == g2.block_hash
    assert g1.height == 0
    assert g1.txs_hash == m.sha256(b"")
    recomputed = m.sha256(m.header_bytes(g1.prev_hash, g1.txs_hash, g1.timestamp, g1.difficulty, g1.nonce))
    assert g1.block_hash == recomputed
    assert len(m.header_bytes(g1.prev_hash, g1.txs_hash, g1.timestamp, g1.difficulty, g1.nonce)) == 84
    print("genesis:", g1.block_hash.hex())

    # 3. count_leading_zeros
    assert m.count_leading_zeros(0) == 256
    assert m.count_leading_zeros(1) == 255
    assert m.count_leading_zeros((1 << 255)) == 0

    # 4. body commitment
    assert m.compute_txs_hash([]) == m.sha256(b"")
    h1 = m.sha256(b"a"); h2 = m.sha256(b"b")
    assert m.compute_txs_hash([h1, h2]) == m.sha256(h1 + h2)

    # 5. validate_block on a hand-mined block extending genesis
    prev = g1.block_hash
    txsh = m.compute_txs_hash([])
    ts, diff = 1, 8
    prefix = prev + txsh + ts.to_bytes(8, "big") + diff.to_bytes(4, "big")
    nonce = 0
    while True:
        bh = m.sha256(prefix + nonce.to_bytes(8, "big"))
        if m.count_leading_zeros(int.from_bytes(bh, "big")) >= diff:
            break
        nonce += 1
    blk = m.Block(1, prev, txsh, bh, ts, diff, nonce)
    blk.tx_hashes = []
    chain = m.Chain()
    assert chain.validate_block(blk, chain.tip()), "validate_block should accept a correctly mined block"
    # tamper -> reject (demand impossible difficulty)
    bad = m.Block(1, prev, txsh, bh, ts, diff + 200, nonce)
    bad.tx_hashes = []
    assert not chain.validate_block(bad, chain.tip())

    # 6. transaction signature round-trip
    from ipv8.keyvault.crypto import default_eccrypto
    key = default_eccrypto.generate_key("curve25519")
    sender_key = key.pub().key_to_bin()
    data = b"hello-tx"
    tts = 1718000000
    sig = default_eccrypto.create_signature(key, sender_key + data + tts.to_bytes(8, "big"))
    assert m.BlockchainCommunity._valid_tx_signature(sender_key, data, tts, sig)
    assert not m.BlockchainCommunity._valid_tx_signature(sender_key, b"tampered", tts, sig)
    th = m.tx_hash(sender_key, data, tts, sig)
    assert th == m.sha256(sender_key + data + tts.to_bytes(8, "big") + sig)

    # 7. payload serialization round-trips (proves (format, value) ordering is right)
    from ipv8.messaging.serialization import default_serializer as S

    def roundtrip(payload, cls, fields):
        raw = S.pack_serializable(payload)
        obj, _ = S.unpack_serializable(cls, raw)
        for f in fields:
            assert getattr(obj, f) == getattr(payload, f), (cls.__name__, f)

    roundtrip(m.RegisterBlockchain("grp-42", m.BLOCKCHAIN_COMMUNITY_ID), m.RegisterBlockchain, ["group_id", "community_id"])
    roundtrip(m.RegisterResponse(True, "ok"), m.RegisterResponse, ["success", "message"])
    roundtrip(m.SubmitTx(sender_key, data, tts, sig), m.SubmitTx, ["sender_key", "data", "timestamp", "signature"])
    roundtrip(m.SubmitTxResponse(True, th, "accepted"), m.SubmitTxResponse, ["success", "tx_hash", "message"])
    roundtrip(m.GetChainHeight(7), m.GetChainHeight, ["request_id"])
    roundtrip(m.ChainHeightResponse(7, 3, prev), m.ChainHeightResponse, ["request_id", "height", "tip_hash"])
    roundtrip(m.GetBlock(2), m.GetBlock, ["height"])
    roundtrip(m.BlockResponse(1, prev, txsh, ts, diff, nonce, bh, b""), m.BlockResponse,
              ["height", "prev_hash", "txs_hash", "timestamp", "difficulty", "nonce", "block_hash", "tx_hashes"])
    roundtrip(m.NewBlock(1, prev, txsh, ts, diff, nonce, bh, h1 + h2), m.NewBlock, ["height", "prev_hash", "tx_hashes"])
    roundtrip(m.GetFullChain(0), m.GetFullChain, ["from_height"])
    roundtrip(m.ChainBlock(1, prev, txsh, ts, diff, nonce, bh, b""), m.ChainBlock, ["height", "block_hash"])
    roundtrip(m.TxGossip(sender_key, data, tts, sig), m.TxGossip, ["sender_key", "data", "timestamp", "signature"])

    # 8. msg_id uniqueness within each overlay
    reg_ids = [m.RegisterBlockchain.msg_id, m.RegisterResponse.msg_id]
    assert len(set(reg_ids)) == len(reg_ids)
    chain_ids = [m.SubmitTx.msg_id, m.SubmitTxResponse.msg_id, m.GetChainHeight.msg_id,
                 m.ChainHeightResponse.msg_id, m.GetBlock.msg_id, m.BlockResponse.msg_id,
                 m.NewBlock.msg_id, m.GetFullChain.msg_id, m.ChainBlock.msg_id, m.TxGossip.msg_id]
    assert len(set(chain_ids)) == len(chain_ids), chain_ids


if __name__ == "__main__":
    test_primitives()
    print("ALL PRIMITIVE CHECKS PASSED")
