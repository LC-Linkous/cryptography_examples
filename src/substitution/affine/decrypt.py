#!/usr/bin/python3

##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/substitution/affine/decrypt.py'
#   Affine cipher decryption class
#
#   Two roles, matching the repo:
#     1. LEGITIMATE decryption: x = a^-1 * (y - b) mod 26, using the modular
#        inverse of the multiplicative key.
#     2. The ATTACK: only 312 keys, so exhaustive search is trivial -- try
#        every (a,b), score by English frequency, return the best. (Frequency
#        analysis on the ciphertext alone also works, since it is still
#        monoalphabetic; brute force is shown here as the simplest method.)
#
#   Author(s): Lauren Linkous  (with Claude AI for structure/commentary)
#   Last update: June 02, 2026
##--------------------------------------------------------------------\

import numpy as np
from math import gcd
from collections import Counter

np.seterr(all='raise')


class decrypt:

    def __init__(self, dictionary=None, opt_df=None, parent=None):
        self.parent = parent
        self.original_dictionary = dictionary

        self.a = int(opt_df['A'][0]) if 'A' in opt_df.columns else 5
        self.b = int(opt_df['B'][0]) if 'B' in opt_df.columns else 8
        self.show_steps = opt_df['SHOW_STEPS'][0] if 'SHOW_STEPS' in opt_df.columns else False
        self.m = 26

        self.lang_freq = {
            'E': 12.7, 'T': 9.1, 'A': 8.2, 'O': 7.5, 'I': 7.0, 'N': 6.7,
            'S': 6.3, 'H': 6.1, 'R': 6.0, 'D': 4.3, 'L': 4.0, 'C': 2.8,
            'U': 2.8, 'M': 2.4, 'W': 2.4, 'F': 2.2, 'G': 2.0, 'Y': 2.0,
            'P': 1.9, 'B': 1.3, 'V': 1.0, 'K': 0.8, 'J': 0.15, 'X': 0.15,
            'Q': 0.10, 'Z': 0.07
        }
        self.valid_a = [a for a in range(1, 26) if gcd(a, 26) == 1]

    def mod_inverse(self, a, m):
        # Extended Euclidean inverse (a is coprime with m by construction).
        for x in range(1, m):
            if (a * x) % m == 1:
                return x
        raise ValueError(f"No inverse for {a} mod {m}")

    def decrypt_message(self, ciphertext, a=None, b=None):
        a = self.a if a is None else a
        b = self.b if b is None else b
        a_inv = self.mod_inverse(a, self.m)
        result = []
        for ch in ciphertext:
            if ch.isalpha():
                y = ord(ch.upper()) - ord('A')
                x = (a_inv * (y - b)) % self.m
                dec = chr(x + ord('A'))
                if ch.islower():
                    dec = dec.lower()
                result.append(dec)
            else:
                result.append(ch)
        return ''.join(result)

    def _score_english(self, text):
        clean = [c for c in text.upper() if c.isalpha()]
        if not clean:
            return -1e9
        counts = Counter(clean)
        total = len(clean)
        score = 0.0
        for letter, cnt in counts.items():
            observed = (cnt / total) * 100
            expected = self.lang_freq.get(letter, 0)
            score -= (observed - expected) ** 2
        common = ['THE', 'AND', 'THAT', 'HAVE', 'FOR', 'WITH', 'THIS']
        score += sum(15 for w in common if w in text.upper())
        return score

    def brute_force_decrypt(self, ciphertext, top_n=5):
        print(f"=== Affine Brute-Force Attack ===")
        print(f"  Only {len(self.valid_a)} valid 'a' x 26 'b' = "
              f"{len(self.valid_a)*26} keys. Exhaustive search is trivial.")
        print("-" * 60)
        results = []
        for a in self.valid_a:
            for b in range(26):
                pt = self.decrypt_message(ciphertext, a, b)
                results.append((a, b, pt, self._score_english(pt)))
        results.sort(key=lambda r: r[3], reverse=True)
        print(f"  Top {top_n} candidates by English score:")
        for i, (a, b, pt, sc) in enumerate(results[:top_n]):
            print(f"    {i+1}. a={a:2d} b={b:2d} (score {sc:7.1f}): "
                  f"{pt[:40]}{'...' if len(pt) > 40 else ''}")
        return results[0]

    def show_affine_state(self):
        print(f"Affine Decrypt State Information:")
        print(f"  D(y) = a^-1 * (y - b) mod 26, with a={self.a}, b={self.b}")
        print(f"  Valid multiplicative keys: {self.valid_a}")

    def get_cipher_stats(self):
        return {
            'cipher_name': 'Affine Decrypt',
            'multiplicative_key_a': self.a,
            'additive_key_b': self.b,
            'valid_a_count': len(self.valid_a),
            'total_keys': len(self.valid_a) * 26,
            'type': 'monoalphabetic substitution'}
