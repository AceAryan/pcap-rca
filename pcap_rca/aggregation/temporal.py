"""How a group's events are spread over time (docs/event_types.md §6).

Checked in this order, first match wins:
    PERIODIC    >= 4 events, gaps of >= periodic_min_gap s with a coefficient of
                variation below periodic_max_cv (timers: retries, cron, idle timeouts)
    ESCALATING  >= 2 x burst_min_events, rate never drops across 4 equal windows
                and the last window has at least twice the first
    BURST       >= burst_min_events within some burst_window
    ISOLATED    fewer than burst_min_events in total
    SUSTAINED   many events, but never burst_min_events within burst_window
"""
from __future__ import annotations

from statistics import fmean, pstdev

ISOLATED, BURST, PERIODIC, ESCALATING, SUSTAINED = (
    "ISOLATED", "BURST", "PERIODIC", "ESCALATING", "SUSTAINED")


def peak_count(times: list[float], window: float) -> int:
    """Most events inside any interval of length `window` (times sorted)."""
    best, lo = 0, 0
    for hi, t in enumerate(times):
        while t - times[lo] > window:
            lo += 1
        best = max(best, hi - lo + 1)
    return best


def window_counts(times: list[float], bins: int) -> list[int]:
    start, span = times[0], times[-1] - times[0]
    counts = [0] * bins
    for t in times:
        counts[min(int((t - start) / span * bins), bins - 1)] += 1
    return counts


def temporal_pattern(times: list[float], cfg) -> tuple[str, dict]:
    ts = sorted(times)
    n = len(ts)
    info: dict = {"count": n, "span": ts[-1] - ts[0] if n else 0.0}
    if n == 0:
        return ISOLATED, info
    info["peak_in_window"] = peak_count(ts, cfg.burst_window)

    if n >= 4:
        gaps = [b - a for a, b in zip(ts, ts[1:])]
        mean = fmean(gaps)
        if mean >= cfg.periodic_min_gap:
            cv = pstdev(gaps) / mean
            if cv < cfg.periodic_max_cv:
                info.update(period=mean, cv=cv)
                return PERIODIC, info

    if n >= 2 * cfg.burst_min_events and info["span"] > 0:
        counts = window_counts(ts, 4)
        if (all(a <= b for a, b in zip(counts, counts[1:]))
                and counts[-1] >= 2 * max(counts[0], 1)):
            info["window_counts"] = counts
            return ESCALATING, info

    if info["peak_in_window"] >= cfg.burst_min_events:
        return BURST, info
    if n < cfg.burst_min_events:
        return ISOLATED, info
    return SUSTAINED, info
