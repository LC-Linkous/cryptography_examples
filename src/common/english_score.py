#!/usr/bin/python3

##--------------------------------------------------------------------\
#   cryptography_examples
#   './cryptography_examples/src/common/english_score.py'
#   Shared "how English is this text?" scorer for the brute-force
#   decrypt classes.
#
#   WHY THIS FILE EXISTS
#   The same ENGLISH_FREQ table and the same scoring loop were copy-pasted
#   into 11 decrypt files. The copied scorer only sums the squared error
#   over letters that APPEAR in the candidate text, so a candidate that
#   uses few distinct letters is penalized less than real English, which
#   uses many. The README's own Caesar example shows the result: the
#   garbage 'aXeeh phkeW' outranks 'HELLO WORLD'.
#
#   The fix is the textbook chi-squared statistic over ALL 26 letters:
#   missing letters (expected but absent) now count against a candidate.
#
#   TWO ENTRY POINTS
#   chi_squared_score() - the raw statistic. Use it when every candidate
#       has the same letters (e.g. the 26 Caesar shifts of one message).
#   english_score()     - the same statistic per letter, minus a penalty
#       for non-letter characters. Use it when candidates differ in length
#       or may be undecodable bytes (Bacon, grids, stream ciphers). The
#       decrypt classes use this one and add their own word/bigram bonuses.
#
#   Frequency alone cannot rank TRANSPOSITION candidates (rail fence):
#   rearranging letters leaves the counts unchanged, so every candidate
#   scores the same and only the word/bigram bonuses decide.
#
#   Author(s): Lauren Linkous
##--------------------------------------------------------------------\

import re
from collections import Counter

# Relative letter frequencies (percent) for English text.
ENGLISH_FREQ = {
    'E': 12.7, 'T': 9.1, 'A': 8.2, 'O': 7.5, 'I': 7.0, 'N': 6.7,
    'S': 6.3, 'H': 6.1, 'R': 6.0, 'D': 4.3, 'L': 4.0, 'C': 2.8,
    'U': 2.8, 'M': 2.4, 'W': 2.4, 'F': 2.2, 'G': 2.0, 'Y': 2.0,
    'P': 1.9, 'B': 1.3, 'V': 1.0, 'K': 0.8, 'J': 0.15, 'X': 0.15,
    'Q': 0.10, 'Z': 0.07,
}


def letters_only(text):
    """Upper-case the text and drop everything that is not A-Z."""
    return re.sub(r'[^A-Z]', '', text.upper())


def chi_squared_score(text, lang_freq=None):
    """Return a score where HIGHER means more English-like.

    This is the negative chi-squared statistic:
        -sum_over_all_letters (observed - expected)^2 / expected
    Summing over every letter in the table (not just the ones present)
    is what makes it work on short texts.
    """
    freq = ENGLISH_FREQ if lang_freq is None else lang_freq
    clean = letters_only(text)
    n = len(clean)
    if n == 0:
        return float('-inf')

    counts = Counter(clean)
    score = 0.0
    for letter, pct in freq.items():
        expected = pct / 100.0 * n
        if expected <= 0:
            continue
        observed = counts.get(letter, 0)
        score -= (observed - expected) ** 2 / expected
    return score


# How much a candidate loses for each non-letter character (as a share of
# its non-space characters). Decrypting with a wrong key often produces
# bytes that print as digits, hex or symbols with only a few stray letters;
# without this, "3E4A" has fewer letters to be wrong about than "HELLO".
NONLETTER_PENALTY = 10.0


def english_score(text, lang_freq=None):
    """Length-independent score for comparing candidates of DIFFERENT lengths.

    chi_squared_score() grows with the number of letters, which is fine
    when every candidate has the same number of letters (Caesar shifts of one
    ciphertext) but unfair when they do not (Bacon symbol guesses, wrong
    stream-cipher keys, grid guesses that leave coordinates undecoded).
    Dividing by the letter count gives the average error per letter, and
    the non-letter penalty stops mostly-garbage candidates from winning.
    Scaled by 100 so word/bigram bonuses in the decrypt classes stay small
    by comparison. HIGHER means more English-like.
    """
    n = len(letters_only(text))
    if n == 0:
        return float('-inf')
    visible = sum(1 for ch in text if not ch.isspace())
    nonletter_share = 1.0 - n / visible
    per_letter = chi_squared_score(text, lang_freq) / n
    return 100.0 * (per_letter - NONLETTER_PENALTY * nonletter_share)


def rank_candidates(candidates, lang_freq=None):
    """Sort (label, text) pairs best-first by chi_squared_score."""
    scored = [(label, text, chi_squared_score(text, lang_freq))
              for label, text in candidates]
    scored.sort(key=lambda t: t[2], reverse=True)
    return scored
