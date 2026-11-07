from common.english_score import chi_squared_score, rank_candidates


def test_real_english_beats_garbage_on_short_text():
    # This exact pair comes from the README's Caesar output, where the old
    # scorer ranked the garbage first.
    assert chi_squared_score("HELLO WORLD") > chi_squared_score("aXeeh phkeW")


def test_all_26_letters_contribute():
    # A text that uses only one letter should score worse than ordinary
    # English, because every *missing* letter now counts against it.
    # (Don't use a pangram here: "the quick brown fox" is deliberately
    # un-English in its letter mix and scores badly under any frequency test.)
    assert chi_squared_score("EEEEEEEEEE") < chi_squared_score("MEET ME AT THE OLD BRIDGE AT NOON")


def test_recovers_caesar_shift_on_a_sentence():
    pt = "MEET ME AT THE OLD BRIDGE AT NOON TONIGHT"
    shift = lambda t, k: ''.join(chr((ord(c) - 65 + k) % 26 + 65) if c.isalpha() else c for c in t)
    ct = shift(pt, 3)
    ranked = rank_candidates([(k, shift(ct, -k)) for k in range(26)])
    assert ranked[0][0] == 3


def test_empty_text_is_worst():
    assert chi_squared_score("!!! 123") == float('-inf')


def test_rank_candidates_orders_best_first():
    ranked = rank_candidates([("junk", "ZXQJ ZXQJ"), ("real", "ATTACK AT DAWN")])
    assert ranked[0][0] == "real"
