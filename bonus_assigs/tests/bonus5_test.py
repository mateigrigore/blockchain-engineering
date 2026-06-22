"""bonus5_test.py -- exercises bonus5_adaptive_difficulty.py.

run from the project root with `python3 -m src.bonus_assigs.tests.bonus5_test`.
no IPv8, no network, no mining: difficulty is a pure function of block headers,
so synthetic (timestamp, bits) tuples are all it needs. the interesting check is
a closed-loop simulation that holds block time roughly steady through a tenfold
hashrate swing, plus a check that a single lying timestamp barely moves anything.
"""

import os
import sys

# make the repo root importable so `bonus_assigs` resolves whether this file is
# run as a script or collected by pytest from any working directory.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from bonus_assigs.bonus5_adaptive_difficulty import (
    DEFAULT_PARAMS,
    RetargetParams,
    cumulative_work,
    is_timestamp_acceptable,
    next_difficulty,
)


def build_steady_history(bits: int, count: int, params: RetargetParams) -> list:
    """make `count` blocks spaced exactly one target interval apart at fixed bits."""
    timestamp = 1000
    history = []
    for _ in range(count):
        timestamp += params.target_interval
        history.append((timestamp, bits))
    return history


def check_steady_state() -> None:
    """blocks arriving on time at constant difficulty should hold that difficulty."""
    params = DEFAULT_PARAMS
    history = build_steady_history(bits=18, count=params.window + 1, params=params)
    result = next_difficulty(history, params)
    assert result == 18, result
    print(f"1) steady state at target interval -> difficulty stays {result}")


def check_doubled_hashrate() -> None:
    """blocks arriving twice as fast should push difficulty up about one bit."""
    params = DEFAULT_PARAMS
    timestamp = 1000
    history = []
    for _ in range(params.window + 1):
        timestamp += params.target_interval // 2   # twice as fast
        history.append((timestamp, 18))
    result = next_difficulty(history, params)
    assert result == 19, result
    print(f"2) hashrate doubled (intervals halved) -> difficulty 18 -> {result}")


def simulate_block_time(hashrate_for_height, total_blocks: int,
                        params: RetargetParams):
    """closed loop: difficulty reacts to history, block time = work / hashrate.

    returns the list of realized inter-block intervals. this is a test harness,
    so it may use floats; the consensus rule (next_difficulty) stays integer.
    """
    blocks = []
    timestamp = 1000
    intervals = []
    for height in range(1, total_blocks + 1):
        bits = next_difficulty(blocks, params)
        hashrate = hashrate_for_height(height)
        interval = (1 << bits) / hashrate          # expected seconds to mine
        timestamp += interval
        blocks.append((int(timestamp), bits))
        intervals.append(interval)
    return intervals


def check_tenfold_swing_holds_block_time() -> None:
    """hold average block time near target through a 10x hashrate jump."""
    params = DEFAULT_PARAMS
    base_rate = (1 << params.bootstrap_difficulty) / params.target_interval

    # hashrate jumps 10x at the halfway point.
    def hashrate_for_height(height: int) -> float:
        return base_rate if height < 150 else base_rate * 10

    intervals = simulate_block_time(hashrate_for_height, total_blocks=300, params=params)
    # look only at the settled tail, well after the jump.
    tail = intervals[-60:]
    average = sum(tail) / len(tail)
    # whole-bit difficulty means at best ~1.41x error, so allow a 1.6x band.
    assert params.target_interval / 1.6 <= average <= params.target_interval * 1.6, average
    print(
        f"3) 10x hashrate jump: settled average block time "
        f"{average:.1f}s vs target {params.target_interval}s"
    )


def check_single_liar_barely_moves_difficulty() -> None:
    """one wildly inflated timestamp must not swing the next difficulty much."""
    params = DEFAULT_PARAMS
    honest = build_steady_history(bits=18, count=params.window + 1, params=params)
    honest_result = next_difficulty(honest, params)

    # a liar pushes the latest block's timestamp a billion seconds into the future.
    liar = honest[:-1] + [(honest[-1][0] + 1_000_000_000, honest[-1][1])]
    liar_result = next_difficulty(liar, params)

    assert abs(liar_result - honest_result) <= 1, (honest_result, liar_result)
    print(
        f"4) single liar (+1e9s timestamp): difficulty {honest_result} -> "
        f"{liar_result} (clamped, barely moves)"
    )


def check_median_timestamp_rule() -> None:
    """a backwards timestamp is rejected by the median-time-past rule."""
    params = DEFAULT_PARAMS
    recent = [1000 + 10 * i for i in range(11)]   # increasing timestamps
    assert is_timestamp_acceptable(recent[-1] + 5, recent, params) is True
    assert is_timestamp_acceptable(recent[0] - 100, recent, params) is False
    print("5) median-time-past rule accepts forward, rejects backwards timestamps")


def check_cumulative_work_beats_length() -> None:
    """a shorter, higher-difficulty chain should out-weigh a longer easy one."""
    long_easy = [10] * 100        # 100 blocks at 10 bits
    short_hard = [20] * 60        # 60 blocks at 20 bits
    assert cumulative_work(short_hard) > cumulative_work(long_easy)
    print(
        f"6) cumulative work: 60x(2^20) = {cumulative_work(short_hard)} "
        f"> 100x(2^10) = {cumulative_work(long_easy)}"
    )


def run_all_checks() -> None:
    """run every adaptive-difficulty check."""
    check_steady_state()
    check_doubled_hashrate()
    check_tenfold_swing_holds_block_time()
    check_single_liar_barely_moves_difficulty()
    check_median_timestamp_rule()
    check_cumulative_work_beats_length()
    print("\nALL ADAPTIVE-DIFFICULTY CHECKS PASSED")


def test_adaptive_difficulty():
    """pytest entry point: run the full adaptive-difficulty check suite."""
    run_all_checks()


if __name__ == "__main__":
    run_all_checks()