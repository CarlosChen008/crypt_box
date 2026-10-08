"""Dictionary attack using a user wordlist or the bundled common passwords."""

import os

from .search import search

_DATA_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                          "data", "common_passwords.txt")


def default_wordlist():
    with open(_DATA_FILE, "r", encoding="utf-8") as handle:
        return [line.strip() for line in handle if line.strip()]


def crack_dictionary(algo, target, words, salt="", progress=None, stop_event=None):
    return search(algo, target, iter(words), salt, progress, stop_event)


def crack_dictionary_file(algo, target, path, salt="", progress=None, stop_event=None):
    def generator():
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                word = line.rstrip("\r\n")
                if word:
                    yield word

    return search(algo, target, generator(), salt, progress, stop_event)
