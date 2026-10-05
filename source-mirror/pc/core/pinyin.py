"""Pinyin helpers that mirror Android's ``com.vault.model.Pinyin``.

Android derives two things from an entry title:

* ``titleSortKey`` — the whole title transliterated to lowercase pinyin so that
  Chinese and Latin titles sort together alphabetically (``苹果`` and ``apple``
  land in the same P segment).
* ``firstLetter`` — the sidebar index letter: digits/symbols fall under ``#``,
  Latin keeps its own letter, and Chinese uses the pinyin initial.

``pypinyin`` backs the transliteration; diacritics are stripped (matching
Android's ``Latin-ASCII`` step) so ``École`` → ``ecole`` → ``E``.
"""

from __future__ import annotations

import unicodedata
from functools import lru_cache

from pypinyin import Style, lazy_pinyin

_NON_COMBINING = unicodedata.combining


def _strip_diacritics(text: str) -> str:
    return "".join(ch for ch in unicodedata.normalize("NFKD", text) if not _NON_COMBINING(ch))


@lru_cache(maxsize=8192)
def pinyin_sort_key(title: str) -> str:
    """Sidebar sort key: Chinese → lowercase pinyin, Latin/others kept as-is.

    Mirrors Android ``Pinyin.sortKey`` so the PC list order matches the Android
    list (sorted by ``titleSortKey``).
    """
    if not title:
        return ""
    syllables = lazy_pinyin(title, style=Style.NORMAL, errors="default")
    return _strip_diacritics("".join(syllables)).lower()


@lru_cache(maxsize=8192)
def pinyin_first_letter(title: str) -> str:
    """Sidebar index letter, mirroring Android ``Pinyin.firstLetter``.

    Empty, digit-leading or symbol-leading titles map to ``#``; an English title
    keeps its first letter; a Chinese title uses the pinyin initial.
    """
    stripped = title.strip()
    if not stripped:
        return "#"
    first = stripped[0]
    if first.isdigit() or not first.isalpha():
        return "#"
    key = pinyin_sort_key(stripped)
    for ch in key:
        if "a" <= ch <= "z":
            return ch.upper()
    return "#"
