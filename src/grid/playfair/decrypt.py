#!/usr/bin/python3

##--------------------------------------------------------------------\
#   cryptography_examples
#   './cryptography_examples/src/grid/playfair/decrypt.py'
#   Playfair cipher decryption class
#
#   Two roles, matching the other decrypt classes in this repo:
#     1. LEGITIMATE decryption: with the keyword, reverse the three
#        Playfair rules to recover the plaintext.
#     2. The ATTACK: the Playfair keyspace is 25! squares, so exhaustive
#        search is hopeless. The realistic classical attack is a KEYWORD
#        DICTIONARY search, scoring each candidate by English letter
#        frequency - the same scoring approach used by the substitution and
#        RC4 decrypt classes here. (A full break uses simulated annealing on
#        digraph frequencies; that is noted but left as a 'decrypt_improved'
#        style extension.)
#
#   Note on readability: Playfair output drops the pad letters it inserted,
#   so a recovered message may contain a stray X between doubled letters or
#   a trailing X. This is expected and is part of the lesson.
#
#   Author(s): Lauren Linkous  (with Claude AI for structure/commentary)
#   Last update: June 02, 2026
##--------------------------------------------------------------------\

import numpy as np
import os
import sys

# Allow 'from common...' whether this file is run from its own folder (the
# repo convention) or imported from the tests/ directory.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))
from common.english_score import ENGLISH_FREQ, english_score

np.seterr(all='raise')


class decrypt:

    def __init__(self, dictionary=None, opt_df=None, parent=None):

        self.parent = parent
        self.original_dictionary = dictionary

        self.keyword = opt_df['KEYWORD'][0] if 'KEYWORD' in opt_df.columns else 'KEYWORD'
        self.combine = opt_df['COMBINE'][0] if 'COMBINE' in opt_df.columns else 'J'
        self.pad = opt_df['PAD'][0] if 'PAD' in opt_df.columns else 'X'
        self.show_steps = opt_df['SHOW_STEPS'][0] if 'SHOW_STEPS' in opt_df.columns else False

        self.kept = 'I' if self.combine.upper() == 'J' else 'A'
        self.alphabet = ''.join(
            ch for ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if ch != self.combine.upper())

        self.square = self._build_square(self.keyword)
        self.pos = {self.square[r][c]: (r, c) for r in range(5) for c in range(5)}

        # English letter frequencies for scoring brute-force candidates
        # (same table used by the substitution/RC4 decrypt classes).
        self.lang_freq = dict(ENGLISH_FREQ)

        # A small keyword dictionary for the demo attack. Tied to the demo
        # use cases (as in the other decrypt classes); extend as desired.
        self.brute_force_keywords = [
            'KEYWORD', 'SECRET', 'CIPHER', 'PLAYFAIR', 'MONARCHY',
            'PASSWORD', 'CRYPTO', 'EXAMPLE', 'MESSAGE', 'HIDDEN',
            'PRIVATE', 'ENCRYPT', 'DECODE', 'PUZZLE', 'WHEATSTONE',
        ]


    def _build_square(self, keyword):
        seen, seen_set = [], set()
        source = keyword.upper() + self.alphabet
        for ch in source:
            if not ch.isalpha():
                continue
            if ch == self.combine.upper():
                ch = self.kept
            if ch not in seen_set and ch in self.alphabet:
                seen_set.add(ch)
                seen.append(ch)
        return [seen[i*5:(i+1)*5] for i in range(5)]


    def _decrypt_pair(self, a, b, square, pos):
        # Inverse of the three rules: shift LEFT / UP instead of right/down;
        # the rectangle rule is its own inverse.
        (r1, c1) = pos[a]
        (r2, c2) = pos[b]
        if r1 == r2:
            return square[r1][(c1 - 1) % 5] + square[r2][(c2 - 1) % 5]
        elif c1 == c2:
            return square[(r1 - 1) % 5][c1] + square[(r2 - 1) % 5][c2]
        else:
            return square[r1][c2] + square[r2][c1]


    def decrypt_message(self, ciphertext, keyword=None):
        # Legitimate decryption with a known keyword.
        if keyword is None:
            keyword = self.keyword
        square = self._build_square(keyword)
        pos = {square[r][c]: (r, c) for r in range(5) for c in range(5)}

        clean = ''.join(ch for ch in ciphertext.upper() if ch.isalpha())
        if self.show_steps:
            print(f"\n=== Playfair Decryption (keyword '{keyword.upper()}') ===")

        out = []
        for i in range(0, len(clean) - 1, 2):
            out.append(self._decrypt_pair(clean[i], clean[i+1], square, pos))
        result = ''.join(out)
        if self.show_steps:
            print(f"  Ciphertext: {clean}")
            print(f"  Decrypted : {result}  (pad letters may remain; see notes)")
        return result


    def calculate_english_score(self, text):
        # Frequency-based score (shared per-letter chi-squared), plus a small
        # bonus for common English words - identical idea to the other
        # decrypt classes.
        clean = ''.join(ch for ch in text.upper() if ch.isalpha())
        if not clean:
            return float('-inf')
        # Shared chi-squared over ALL letters, per letter (common/english_score.py):
        # letters English expects but the candidate lacks now count against it.
        score = english_score(text, self.lang_freq)
        common = ['THE', 'AND', 'THAT', 'HAVE', 'FOR', 'NOT', 'WITH',
                  'YOU', 'THIS', 'BUT', 'HIS', 'FROM', 'THEY']
        score += sum(15 for w in common if w in text.upper())
        return score


    def brute_force_decrypt(self, ciphertext, show_all=False):
        # Keyword-dictionary attack: try each candidate keyword, score the
        # resulting plaintext by English-likeness, return ranked results.
        print(f"=== Playfair Keyword-Dictionary Attack ===")
        print(f"  Keyspace is 25! squares - exhaustive search is hopeless.")
        print(f"  Trying {len(self.brute_force_keywords)} candidate keywords, "
              f"scored by English frequency.")
        print("-" * 60)

        results = []
        for kw in self.brute_force_keywords:
            try:
                pt = self.decrypt_message(ciphertext, keyword=kw)
                score = self.calculate_english_score(pt)
                results.append((kw, pt, score))
                if show_all:
                    print(f"  {kw:12s} -> {pt[:30]:<30} (score {score:.1f})")
            except Exception as e:
                if show_all:
                    print(f"  {kw:12s} -> ERROR: {e}")

        results.sort(key=lambda x: x[2], reverse=True)
        return results


    def auto_decrypt(self, ciphertext, top_n=5):
        results = self.brute_force_decrypt(ciphertext, show_all=False)
        print(f"\n  Top {top_n} candidates by English score:")
        print("-" * 60)
        for i, (kw, pt, score) in enumerate(results[:top_n]):
            print(f"  {i+1}. keyword '{kw}' (score {score:.1f}): {pt}")
        return results[0] if results else None


    def show_playfair_state(self):
        print(f"Playfair Decrypt State Information:")
        print(f"  Keyword: {self.keyword.upper()}")
        print(f"  Combined letters: {self.combine.upper()}/{self.kept}")
        print(f"  Pad letter: {self.pad}")
        print(f"  5x5 key square:")
        for row in self.square:
            print(f"    {' '.join(row)}")


    def get_cipher_stats(self):
        return {
            'cipher_name': 'Playfair Decrypt',
            'keyword': self.keyword.upper(),
            'combine': f"{self.combine.upper()}/{self.kept}",
            'pad': self.pad,
            'dictionary_size': len(self.brute_force_keywords),
            'unit': 'digraph (letter pairs)'}
