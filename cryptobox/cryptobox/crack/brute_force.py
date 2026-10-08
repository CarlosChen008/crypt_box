"""Brute-force attack over a configurable character set and length range."""

import itertools

from .search import search


def crack_brute_force(algo, target, charset, min_len, max_len, salt="",
                      progress=None, stop_event=None):
    if not charset or max_len < 1:
        raise ValueError("charset must be non-empty and max length >= 1")
    min_len = max(1, min_len)

    def generator():
        for length in range(min_len, max_len + 1):
            for combo in itertools.product(charset, repeat=length):
                yield "".join(combo)

    return search(algo, target, generator(), salt, progress, stop_event)
