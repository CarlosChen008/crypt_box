"""Shared search loop for attacks against locally implemented hashes."""

import time

from ..core.hashes import digest_hex


def _salted(candidate: str, salt: str) -> str:
    return candidate + salt if salt else candidate


def search(algo, target, candidates, salt="", progress=None, stop_event=None,
           report_every=20000):
    target = target.strip().lower()
    attempts = 0
    started = time.time()
    for candidate in candidates:
        if stop_event is not None and stop_event.is_set():
            return {"found": False, "plaintext": None, "attempts": attempts,
                    "stopped": True, "seconds": time.time() - started}
        attempts += 1
        if digest_hex(algo, _salted(candidate, salt).encode("utf-8")) == target:
            return {"found": True, "plaintext": candidate, "attempts": attempts,
                    "stopped": False, "seconds": time.time() - started}
        if progress is not None and attempts % report_every == 0:
            progress(attempts)
    return {"found": False, "plaintext": None, "attempts": attempts,
            "stopped": False, "seconds": time.time() - started}
