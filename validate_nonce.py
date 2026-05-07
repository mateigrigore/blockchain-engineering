import hashlib
import struct
import sys

# --- CONFIGURATION (MUST MATCH YOUR MINER EXACTLY) ---
EMAIL = "m.grigore@student.tudelft.nl"
GITHUB_URL = "https://github.com/mateigrigore/blockchain-engineering"
# ------------------------------------------------------

def is_valid_nonce(nonce: int) -> bool:
    """
    Returns True if nonce satisfies the 28-bit PoW condition.
    """

    prefix = f"{EMAIL}\n{GITHUB_URL}\n".encode("utf-8")

    pack = struct.Struct(">q").pack  # 8-byte big-endian signed int64

    h = hashlib.sha256()
    h.update(prefix)
    h.update(pack(nonce))

    digest = h.digest()

    # Difficulty check: 28 leading zero bits
    return digest[:3] == b"\x00\x00\x00" and digest[3] < 16


def main():
    if len(sys.argv) != 2:
        print("Usage: python validate_nonce.py <nonce>")
        sys.exit(1)

    try:
        nonce = int(sys.argv[1])
    except ValueError:
        print("Nonce must be an integer")
        sys.exit(1)

    if nonce < 0 or nonce >= 2**63:
        print("Nonce out of valid range (0 ≤ nonce < 2^63)")
        sys.exit(1)

    if is_valid_nonce(nonce):
        print(f"✅ VALID nonce: {nonce}")
    else:
        print(f"❌ INVALID nonce: {nonce}")


if __name__ == "__main__":
    main()