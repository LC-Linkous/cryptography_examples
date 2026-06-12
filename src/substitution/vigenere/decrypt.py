#!/usr/bin/python3

##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/substitution/vigenere/decrypt.py'
#   Vigenere cipher decryption class
#
#   Two roles, matching the repo's other decrypt classes:
#     1. LEGITIMATE decryption with a known keyword (reverse the shifts).
#     2. The ATTACK -- the historical break of "le chiffre indechiffrable":
#        a) find the KEY LENGTH via the index of coincidence and/or Kasiski
#           examination (repeated-substring spacing);
#        b) split the ciphertext into that many columns, each of which is a
#           simple CAESAR cipher, and solve each by frequency analysis --
#           reusing the same English-frequency scoring as the Caesar and RC4
#           decrypt classes.
#
#   This is the cryptanalytic centerpiece of the polyalphabetic section: it
#   shows WHY a longer key is stronger (more columns, less data per column)
#   and how the index of coincidence detects the period.
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

        # English letter frequencies (proportions), used both for the
        # per-column Caesar solve and for the index-of-coincidence target.
        self.lang_freq = {
            'E': 12.7, 'T': 9.1, 'A': 8.2, 'O': 7.5, 'I': 7.0, 'N': 6.7,
            'S': 6.3, 'H': 6.1, 'R': 6.0, 'D': 4.3, 'L': 4.0, 'C': 2.8,
            'U': 2.8, 'M': 2.4, 'W': 2.4, 'F': 2.2, 'G': 2.0, 'Y': 2.0,
            'P': 1.9, 'B': 1.3, 'V': 1.0, 'K': 0.8, 'J': 0.15, 'X': 0.15,
            'Q': 0.10, 'Z': 0.07
        }
        # The index of coincidence of English text is ~0.0667; of random
        # text, ~1/26 = 0.0385. The IC test exploits this gap.
        self.english_ic = 0.0667
        self.random_ic = 1.0 / 26


    # ---- legitimate decryption ----

    def decrypt_message(self, ciphertext, keyword=None):
        if keyword is None:
            keyword = self.key_clean
        key = ''.join(ch for ch in keyword.upper() if ch.isalpha())
        if not key:
            raise ValueError("Need a keyword to decrypt.")

        result = []
        key_index = 0
        for ch in ciphertext:
            if ch.isalpha():
                shift = ord(key[key_index % len(key)]) - ord('A')
                base = ord('A')
                dec = chr((ord(ch.upper()) - base - shift) % 26 + base)
                if ch.islower():
                    dec = dec.lower()
                result.append(dec)
                key_index += 1
            else:
                result.append(ch)
        return ''.join(result)


    # ---- the attack: step 1, find the key length ----

    def index_of_coincidence(self, text):
        # IC = probability that two randomly chosen letters are equal.
        # = sum_c n_c(n_c - 1) / (N(N-1)).  English ~0.067, random ~0.038.
        letters = [c for c in text.upper() if c.isalpha()]
        N = len(letters)
        if N < 2:
            return 0.0
        counts = Counter(letters)
        return sum(n * (n - 1) for n in counts.values()) / (N * (N - 1))


    def find_key_length_by_ic(self, ciphertext, max_len=None):
        # For each candidate period p, split into p columns and average the
        # IC of the columns. The correct p makes each column monoalphabetic
        # (a Caesar shift of English), so its average IC jumps toward ~0.067.
        max_len = max_len or self.max_key_length
        letters = [c for c in ciphertext.upper() if c.isalpha()]
        results = []
        for p in range(1, max_len + 1):
            columns = [letters[i::p] for i in range(p)]
            ics = [self.index_of_coincidence(''.join(col)) for col in columns if len(col) > 1]
            avg_ic = sum(ics) / len(ics) if ics else 0.0
            results.append((p, avg_ic))
        return results


    def kasiski_examination(self, ciphertext, min_len=3):
        # Find repeated substrings and the GCD-friendly spacings between
        # their occurrences. The key length tends to divide these spacings,
        # because identical plaintext aligned with identical key produces
        # identical ciphertext. We return the distribution of spacing factors.
        letters = ''.join(c for c in ciphertext.upper() if c.isalpha())
        spacings = []
        seen = {}
        for length in range(min_len, min_len + 3):
            for i in range(len(letters) - length + 1):
                sub = letters[i:i + length]
                if sub in seen:
                    spacings.append(i - seen[sub])
                seen[sub] = i
            seen = {}
        # Tally the factors of all spacings; the key length divides many.
        factor_votes = Counter()
        for s in spacings:
            for f in range(2, self.max_key_length + 1):
                if s % f == 0:
                    factor_votes[f] += 1
        return factor_votes


    # ---- the attack: step 2, solve each column as a Caesar ----

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
        return score


    def _best_caesar_shift(self, column):
        # Try all 26 shifts on one column, score each by English frequency,
        # return the best shift (= the key letter for this column).
        best_shift, best_score = 0, -1e18
        for shift in range(26):
            shifted = ''.join(
                chr((ord(c) - ord('A') - shift) % 26 + ord('A')) for c in column)
            sc = self._score_english(shifted)
            if sc > best_score:
                best_score, best_shift = sc, shift
        return best_shift


    def recover_key(self, ciphertext, key_length):
        # Given the key length, recover the keyword letter-by-letter by
        # solving each column as an independent Caesar cipher.
        letters = ''.join(c for c in ciphertext.upper() if c.isalpha())
        columns = [letters[i::key_length] for i in range(key_length)]
        key = ''.join(chr(self._best_caesar_shift(col) + ord('A')) for col in columns)
        return key


    def brute_force_decrypt(self, ciphertext):
        # Full automated attack: IC for key length, Kasiski as corroboration,
        # then per-column Caesar solve, then decrypt with the recovered key.
        print(f"=== Vigenere Cryptanalysis (the historical break) ===")
        print(f"  No keyword supplied -- recovering it from the ciphertext.")
        print("-" * 60)

        # Step 1a: index of coincidence
        ic_results = self.find_key_length_by_ic(ciphertext)
        print(f"  Step 1: index of coincidence per candidate key length")
        print(f"    (English ~{self.english_ic:.4f}, random ~{self.random_ic:.4f})")
        # show the most promising candidates (IC closest to English)
        ranked = sorted(ic_results, key=lambda x: abs(x[1] - self.english_ic))
        for p, ic in ranked[:5]:
            marker = "  <-- likely" if abs(ic - self.english_ic) < 0.008 else ""
            print(f"    length {p:2d}: avg IC = {ic:.4f}{marker}")
        best_len = ranked[0][0]

        # Step 1b: Kasiski corroboration
        votes = self.kasiski_examination(ciphertext)
        if votes:
            top = votes.most_common(3)
            print(f"  Step 1 (corroboration): Kasiski factor votes: {top}")

        print(f"\n  Estimated key length: {best_len}")

        # Step 2: recover the key and decrypt
        recovered_key = self.recover_key(ciphertext, best_len)
        plaintext = self.decrypt_message(ciphertext, recovered_key)
        print(f"  Step 2: solved each of the {best_len} columns as a Caesar cipher")
        print(f"  Recovered keyword: {recovered_key}")
        print(f"  Decrypted: {plaintext[:80]}{'...' if len(plaintext) > 80 else ''}")
        return recovered_key, plaintext


    def show_vigenere_state(self):
        print(f"Vigenere Decrypt State Information:")
        print(f"  Keyword: {self.key_clean if self.key_clean else '(none - attack mode)'}")
        print(f"  Max key length to test: {self.max_key_length}")


    def get_cipher_stats(self):
        return {
            'cipher_name': 'Vigenere Decrypt',
            'keyword': self.key_clean if self.key_clean else '(attack mode)',
            'max_key_length': self.max_key_length,
            'english_ic': self.english_ic,
            'type': 'polyalphabetic substitution'}
