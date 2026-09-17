#!/usr/bin/python3

##--------------------------------------------------------------------\
#   cryptography_examples
#   './cryptography_examples/src/substitution/beaufort/decrypt.py'
#   Beaufort cipher decryption class
#
#   Because Beaufort is RECIPROCAL (P = (K - C) mod 26 has the same form as
#   encryption), legitimate decryption is identical to encryption with the
#   same key. The ATTACK is the same as Vigenere's: the cipher is
#   polyalphabetic with a repeating key, so index-of-coincidence finds the
#   period and each column is then a (Beaufort-style) monoalphabetic cipher
#   solvable by frequency analysis. We find the key length here and show how
#   the per-column solve differs slightly from Vigenere (subtractive, not
#   additive), reusing the same statistical machinery.
#
#   Author(s): Lauren Linkous  (with Claude AI for structure/commentary)
#   Last update: June 02, 2026
##--------------------------------------------------------------------\

import numpy as np
from collections import Counter

np.seterr(all='raise')


class decrypt:

    def __init__(self, dictionary=None, opt_df=None, parent=None):
        self.parent = parent
        self.original_dictionary = dictionary
        self.keyword = opt_df['KEYWORD'][0] if 'KEYWORD' in opt_df.columns else 'KEY'
        self.show_steps = opt_df['SHOW_STEPS'][0] if 'SHOW_STEPS' in opt_df.columns else False
        self.max_key_length = int(opt_df['MAX_KEY_LENGTH'][0]) if 'MAX_KEY_LENGTH' in opt_df.columns else 20
        self.key_clean = ''.join(ch for ch in self.keyword.upper() if ch.isalpha())
        self.lang_freq = {
            'E': 12.7, 'T': 9.1, 'A': 8.2, 'O': 7.5, 'I': 7.0, 'N': 6.7,
            'S': 6.3, 'H': 6.1, 'R': 6.0, 'D': 4.3, 'L': 4.0, 'C': 2.8,
            'U': 2.8, 'M': 2.4, 'W': 2.4, 'F': 2.2, 'G': 2.0, 'Y': 2.0,
            'P': 1.9, 'B': 1.3, 'V': 1.0, 'K': 0.8, 'J': 0.15, 'X': 0.15,
            'Q': 0.10, 'Z': 0.07
        }
        self.english_ic = 0.0667

    def decrypt_message(self, ciphertext, keyword=None):
        # Reciprocal: P = (K - C) mod 26, identical operation to encrypt.
        if keyword is None:
            keyword = self.key_clean
        key = ''.join(ch for ch in keyword.upper() if ch.isalpha())
        result = []
        key_index = 0
        for ch in ciphertext:
            if ch.isalpha():
                K = ord(key[key_index % len(key)]) - ord('A')
                C = ord(ch.upper()) - ord('A')
                P = (K - C) % 26
                dec = chr(P + ord('A'))
                if ch.islower():
                    dec = dec.lower()
                result.append(dec)
                key_index += 1
            else:
                result.append(ch)
        return ''.join(result)

    def index_of_coincidence(self, text):
        letters = [c for c in text.upper() if c.isalpha()]
        N = len(letters)
        if N < 2:
            return 0.0
        counts = Counter(letters)
        return sum(n * (n - 1) for n in counts.values()) / (N * (N - 1))

    def find_key_length_by_ic(self, ciphertext, max_len=None):
        max_len = max_len or self.max_key_length
        letters = [c for c in ciphertext.upper() if c.isalpha()]
        results = []
        for p in range(1, max_len + 1):
            cols = [letters[i::p] for i in range(p)]
            ics = [self.index_of_coincidence(''.join(c)) for c in cols if len(c) > 1]
            results.append((p, sum(ics) / len(ics) if ics else 0.0))
        return results

    def _score_english(self, text):
        clean = [c for c in text.upper() if c.isalpha()]
        if not clean:
            return -1e9
        counts = Counter(clean)
        total = len(clean)
        return -sum(((counts.get(L, 0) / total) * 100 - exp) ** 2
                    for L, exp in self.lang_freq.items())

    def _best_key_letter(self, column):
        # For Beaufort, decrypting a column with key letter k gives
        # P = (k - C) mod 26. Try all 26 k, score, pick the most English.
        best_k, best_score = 0, -1e18
        for k in range(26):
            dec = ''.join(chr((k - (ord(c) - ord('A'))) % 26 + ord('A')) for c in column)
            sc = self._score_english(dec)
            if sc > best_score:
                best_score, best_k = sc, k
        return best_k

    def recover_key(self, ciphertext, key_length):
        letters = ''.join(c for c in ciphertext.upper() if c.isalpha())
        cols = [letters[i::key_length] for i in range(key_length)]
        return ''.join(chr(self._best_key_letter(c) + ord('A')) for c in cols)

    def brute_force_decrypt(self, ciphertext):
        print(f"=== Beaufort Cryptanalysis (same family as Vigenere) ===")
        ic = self.find_key_length_by_ic(ciphertext)
        ranked = sorted(ic, key=lambda x: abs(x[1] - self.english_ic))
        print(f"  Index of coincidence picks key length (English ~{self.english_ic}):")
        for p, v in ranked[:4]:
            mark = "  <-- likely" if abs(v - self.english_ic) < 0.008 else ""
            print(f"    length {p:2d}: IC {v:.4f}{mark}")
        best_len = ranked[0][0]
        key = self.recover_key(ciphertext, best_len)
        pt = self.decrypt_message(ciphertext, key)
        print(f"  Estimated key length {best_len}, recovered key '{key}'")
        print(f"  Decrypted: {pt[:70]}{'...' if len(pt) > 70 else ''}")
        return key, pt

    def show_beaufort_state(self):
        print(f"Beaufort Decrypt State Information:")
        print(f"  Decryption = encryption (reciprocal): P = (K - C) mod 26")
        print(f"  Keyword: {self.key_clean if self.key_clean else '(attack mode)'}")

    def get_cipher_stats(self):
        return {
            'cipher_name': 'Beaufort Decrypt',
            'keyword': self.key_clean if self.key_clean else '(attack mode)',
            'formula': 'P = (K - C) mod 26 (reciprocal)',
            'attack': 'index of coincidence + per-column frequency',
            'type': 'polyalphabetic substitution'}
