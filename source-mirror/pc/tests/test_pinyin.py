"""Parity tests for the PC pinyin helpers against Android's ``Pinyin`` rules.

Android derives two things from an entry title (``com.vault.model.Pinyin``):

* ``firstLetter`` — sidebar index letter: digits/symbols → '#', Latin keeps its
  own letter, Chinese uses the pinyin initial.
* ``sortKey`` — the whole title transliterated to lowercase pinyin so Chinese and
  Latin titles sort together alphabetically.

The PC must produce identical results so the sidebar navigation matches Android.
"""

from core.pinyin import pinyin_first_letter, pinyin_sort_key


def test_first_letter_matches_android_pinyin_first_letter() -> None:
    # Mirrors PinyinFirstLetterTest on Android.
    assert pinyin_first_letter("0011.ai") == "#"
    assert pinyin_first_letter("123pan.com") == "#"
    assert pinyin_first_letter("555yy1.com") == "#"
    assert pinyin_first_letter("10.5.80.24") == "#"
    assert pinyin_first_letter(".hidden") == "#"
    assert pinyin_first_letter("") == "#"
    assert pinyin_first_letter("amazon") == "A"
    assert pinyin_first_letter("baidu.com") == "B"
    assert pinyin_first_letter("QQ") == "Q"


def test_first_letter_chinese_uses_pinyin_initial() -> None:
    assert pinyin_first_letter("微信") == "W"
    assert pinyin_first_letter("苹果") == "P"
    assert pinyin_first_letter("中") == "Z"
    # Diacritics are stripped (Android uses Latin-ASCII), so École → E.
    assert pinyin_first_letter("École") == "E"
    assert pinyin_first_letter("café苹果") == "C"


def test_sort_key_pinyin_orders_chinese_and_latin_together() -> None:
    # Android sorts the list by titleSortKey; Chinese must fall under its pinyin
    # segment, not its Unicode code point.
    titles = ["苹果", "amazon", "安全", "baidu", "微信", "123test"]
    ordered = sorted(titles, key=pinyin_sort_key)
    # 123test → '#' group sorts first by raw text; then the a/b/p segments.
    assert ordered[0] == "123test"
    assert ordered.index("amazon") < ordered.index("安全") < ordered.index("苹果")
    assert ordered.index("baidu") < ordered.index("微信")
    # 安全 (anquan) and amazon both start with 'a' but amazon precedes 安全.
    assert ordered.index("amazon") < ordered.index("安全")
