"""bonus5_adaptive_difficulty.py -- bonus #5: adaptive proof-of-work difficulty.

standalone and stdlib-only, with no IPv8 dependency, so it can be tested on its
own and imported into the node later. the core function is next_difficulty: given
the recent blocks of the chain (their timestamps and declared difficulties), it
returns the difficulty the next block must use, as a whole number of leading-zero
bits to match the server's PoW rule.

key properties:
    deterministic:
                    only integer arithmetic over data already in the chain, so
                    every node computes the identical value and they agree.
    tracks hashpower:
                    works from the inter-block times recorded on the chain,
                    averaged over a fixed window of the most recent blocks.
    deaf to a liar:
                    each interval is clamped, so one bogus timestamp can only move
                    the result a little; a separate median rule rejects backwards
                    timestamps outright.
    bounded steps:
                    difficulty moves at most a few bits per block and stays within
                    safe absolute limits, so the controller settles without ringing.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple

# one block of history: (timestamp_seconds, difficulty_bits).
BlockInfo = Tuple[int, int]


@dataclass(frozen=True)
class RetargetParams:
    """tunable knobs for the retarget; defaults suit a small local network."""
    target_interval: int = 10        # desired seconds between blocks
    window: int = 17                 # how many recent intervals to look at
    max_step: int = 4                # most bits difficulty may move per block
    min_difficulty: int = 1          # never go below this many bits
    max_difficulty: int = 30         # never go above this many bits
    bootstrap_difficulty: int = 1   # difficulty before there is enough history
    clamp_factor: int = 6            # an interval counts as at most this * target
    mtp_window: int = 11             # blocks used for the median-timestamp rule (submitted timestamps must be larger)

    @property
    def min_interval(self) -> int:
        """smallest interval a pair of blocks may contribute (seconds)."""
        return 1

    @property
    def max_interval(self) -> int:
        """largest interval a pair of blocks may contribute (seconds)."""
        return self.target_interval * self.clamp_factor


DEFAULT_PARAMS = RetargetParams()


def block_work(difficulty_bits: int) -> int:
    """work a block represents: roughly the hashes needed, which is 2 ** bits."""
    return 1 << difficulty_bits


def cumulative_work(difficulties: List[int]) -> int:
    """total work of a chain: the sum of each block's work (the fork-choice metric)."""
    total = 0
    for bits in difficulties:
        total += block_work(bits)
    return total


def median_timestamp(timestamps: List[int]) -> int:
    """median of a list of timestamps (lower median for an even count)."""
    ordered = sorted(timestamps)
    middle = len(ordered) // 2
    return ordered[middle] if len(ordered) % 2 else ordered[middle - 1]


def is_timestamp_acceptable(new_timestamp: int, recent_timestamps: List[int],
                            params: RetargetParams = DEFAULT_PARAMS) -> bool:
    """a new block's timestamp must beat the median of the last few blocks.

    this is the median-time-past rule: it stops a miner from claiming time went
    backwards or stalled, which a single block cannot do against a median.
    """
    if not recent_timestamps:
        return True
    window = recent_timestamps[-params.mtp_window:]
    return new_timestamp > median_timestamp(window)


def next_difficulty(recent_blocks: List[BlockInfo],
                    params: RetargetParams = DEFAULT_PARAMS) -> int:
    """compute the difficulty (in bits) the next block must use.

    recent_blocks is the chain's blocks oldest-first, excluding genesis. with
    fewer than two blocks there is no interval to measure, so we use the
    bootstrap difficulty.
    """
    # not enough history to measure a single interval yet.
    if len(recent_blocks) < 2:
        return params.bootstrap_difficulty

    # keep only enough blocks to form `window` intervals.
    window_blocks = recent_blocks[-(params.window + 1):]

    # plain average over the window: total work done divided by total time taken
    # gives an estimate of hashrate, with every interval counted equally.
    total_work = 0
    total_time = 0
    for older, newer in zip(window_blocks, window_blocks[1:]):
        older_timestamp, _ = older
        newer_timestamp, newer_bits = newer
        # clamp the interval so one bad timestamp can only move things a little.
        interval = newer_timestamp - older_timestamp
        interval = max(params.min_interval, min(interval, params.max_interval))
        total_work += block_work(newer_bits)
        total_time += interval

    # the work the next block should need to land on the target interval.
    next_work = params.target_interval * total_work // total_time

    # round that work to the nearest whole bit (nearest power of two in log space).
    bits = max(0, next_work.bit_length() - 1)
    lower = 1 << bits
    upper = 1 << (bits + 1)
    # next_work is closer to the higher bit when it is past the geometric mean.
    if next_work * next_work >= lower * upper:
        bits += 1

    # limit the per-block change, then clamp to the safe absolute range.
    last_bits = window_blocks[-1][1]
    bits = max(last_bits - params.max_step, min(bits, last_bits + params.max_step))
    bits = max(params.min_difficulty, min(bits, params.max_difficulty))
    return bits