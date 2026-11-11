from common.english_score import chi_squared_score, english_score, rank_candidates


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


# ------------------------------------------------- english_score (per letter)

def test_english_score_is_length_independent():
    # The raw chi-squared total grows with the letter count, so a candidate
    # with fewer letters looks "closer" to English. The per-letter score
    # should give the same text the same score at any length.
    assert abs(english_score("ATTACK AT DAWN") - english_score("ATTACK AT DAWN " * 5)) < 1e-6


def test_english_score_rejects_mostly_nonletter_garbage():
    # A wrong RC4 key decodes to bytes the class prints as hex. Before this
    # scorer, '34EE21F1A8' outranked the real plaintext 'HELLO'.
    assert english_score("HELLO") > english_score("34EE21F1A8")
    assert english_score("SECRET") > english_score("10010001A10100010010010011")
    assert english_score("2578821120") == float('-inf')


def test_rc4_brute_force_finds_the_key(load_module, opts):
    import contextlib, io
    dec = load_module('stream/RC4/decrypt.py').decrypt(None, opts(KEY='', INPUT_FORMAT='HEX'))
    with contextlib.redirect_stdout(io.StringIO()):
        best = dec.brute_force_decrypt("D42B203340", max_keys=15)[0]   # 'HELLO' under key 'SECRET'
    assert best[0] == 'SECRET' and best[1] == 'HELLO'


def test_bacon_brute_force_guesses_the_symbols(load_module):
    import contextlib, io
    dec = load_module('substitution/bacon/decrypt.py').decrypt()
    ct = "100100010000010100010010010011"                     # SECRET with 0/1
    with contextlib.redirect_stdout(io.StringIO()):
        best = dec.brute_force_decrypt(ct, show_progress=False)[0]
    assert 'SECRET' in str(best)
