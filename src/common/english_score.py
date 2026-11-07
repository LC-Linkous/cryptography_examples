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


def rank_candidates(candidates, lang_freq=None):
    """Sort (label, text) pairs best-first by chi_squared_score."""
    scored = [(label, text, chi_squared_score(text, lang_freq))
              for label, text in candidates]
    scored.sort(key=lambda t: t[2], reverse=True)
    return scored
