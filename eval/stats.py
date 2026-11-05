"""二项比例的 Wilson 区间。

主表里的 ASR / UA / BTC / FPR 都是「k 次里中了 n 次」这种计数，不是模型输出的
连续测量。Wilson 区间只描述这个计数在重复抽取同样试验时的抽样波动，
不描述换一个模型或换一种注入措辞之后的波动。MockLLM 下同格样本同质，
这一点在报告里必须写明，否则区间会被读成统计显著性。
"""

from __future__ import annotations

import math


def wilson_interval(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """返回比例的 Wilson 95% 区间，取值在 [0, 1]。n=0 时返回 (0, 0)。"""
    if n <= 0:
        return (0.0, 0.0)
    if k < 0 or k > n:
        raise ValueError(f"k 必须落在 0..n 内，得到 k={k} n={n}")
    p = k / n
    z2 = z * z
    denom = 1.0 + z2 / n
    center = (p + z2 / (2.0 * n)) / denom
    margin = z * math.sqrt(p * (1.0 - p) / n + z2 / (4.0 * n * n)) / denom
    return (max(0.0, center - margin), min(1.0, center + margin))


def rate_interval(k: int, n: int) -> dict[str, float | int]:
    """百分数口径的区间，便于直接写进表。low/high 是百分数。"""
    lo, hi = wilson_interval(k, n)
    pct = round(100.0 * k / n, 1) if n else 0.0
    return {
        "k": k,
        "n": n,
        "pct": pct,
        "low": round(100.0 * lo, 1),
        "high": round(100.0 * hi, 1),
    }


def format_rate(k: int, n: int) -> str:
    r = rate_interval(k, n)
    if n <= 0:
        return "—（n=0）"
    return f"{r['pct']}% [{r['low']}, {r['high']}]（k={r['k']}/n={r['n']}）"
