#!/usr/bin/python3

##--------------------------------------------------------------------\
#   cryptography_examples
#   './cryptography_examples/src/substitution/autokey/decrypt.py'
#   Autokey cipher decryption class
#
#   Two roles:
#     1. LEGITIMATE decryption: decrypt the first letters with the primer;
#        each recovered plaintext letter THEN becomes the next key letter.
#        The key stream "unzips" itself as you go -- an elegant feedback.
#     2. The ATTACK: the Kasiski/IC attack on Vigenere FAILS here (no
#        repeating key, no period). The autokey is broken differently: by
#        exploiting that the key stream is itself English plaintext. The
#        classic method tries short primers and looks for a high-probability
#        plaintext fragment, then "extends" it (since plaintext is the key).
#        We implement primer brute force for short primers (the practical
#        case), scoring recovered plaintext by English-likeness.
#
#   This contrast is the whole pedagogical point: the autokey defeats the
#   period-based attack that breaks Vigenere, forcing a fundamentally
#   different (and harder) cryptanalysis.
#
#   Author(s): Lauren Linkous  (with Claude AI for structure/commentary)
#   Last update: June 02, 2026
##--------------------------------------------------------------------\

import numpy as np
from collections import Counter
from itertools import product

np.seterr(all='raise')


class decrypt:

    def __init__(self, dictionary=None, opt_df=None, parent=None):
        self.parent = parent
        self.original_dictionary = dictionary
        self.primer = opt_df['PRIMER'][0] if 'PRIMER' in opt_df.columns else 'KEY'
        self.show_steps = opt_df['SHOW_STEPS'][0] if 'SHOW_STEPS' in opt_df.columns else False
        # primer length to brute force in attack mode
        self.attack_primer_len = int(opt_df['ATTACK_PRIMER_LEN'][0]) if 'ATTACK_PRIMER_LEN' in opt_df.columns else 3
        self.primer_clean = ''.join(ch for ch in self.primer.upper() if ch.isalpha())
        self.lang_freq = {
            'E': 12.7, 'T': 9.1, 'A': 8.2, 'O': 7.5, 'I': 7.0, 'N': 6.7,
            'S': 6.3, 'H': 6.1, 'R': 6.0, 'D': 4.3, 'L': 4.0, 'C': 2.8,
            'U': 2.8, 'M': 2.4, 'W': 2.4, 'F': 2.2, 'G': 2.0, 'Y': 2.0,
            'P': 1.9, 'B': 1.3, 'V': 1.0, 'K': 0.8, 'J': 0.15, 'X': 0.15,
            'Q': 0.10, 'Z': 0.07
        }

    def decrypt_message(self, ciphertext, primer=None):
        # The self-unzipping decryption: primer decrypts the first letters,
        # and each recovered plaintext letter extends the key.
        if primer is None:
            primer = self.primer_clean
        primer = ''.join(ch for ch in primer.upper() if ch.isalpha())
        key_stream = list(primer)   # grows as we recover plaintext
        result = []
        li = 0
        recovered_letters = []
        for ch in ciphertext:
            if ch.isalpha():
                C = ord(ch.upper()) - ord('A')
                K = ord(key_stream[li]) - ord('A')
                P = (C - K) % 26
                p_char = chr(P + ord('A'))
                recovered_letters.append(p_char)
                # the recovered plaintext letter becomes a future key letter
                key_stream.append(p_char)
                dec = p_char.lower() if ch.islower() else p_char
                result.append(dec)
                li += 1
            else:
                result.append(ch)
        return ''.join(result)

    def _score_english(self, text):
        clean = [c for c in text.upper() if c.isalpha()]
        if not clean:
            return -1e9
        counts = Counter(clean)
        total = len(clean)
        score = -sum(((counts.get(L, 0) / total) * 100 - exp) ** 2
                     for L, exp in self.lang_freq.items())
        common = ['THE', 'AND', 'THAT', 'ING', 'ION', 'FOR', 'WITH', 'THIS', 'ARE']
        score += sum(20 for w in common if w in text.upper())
        return score

    def brute_force_decrypt(self, ciphertext, primer_len=None, top_n=5):
        # Brute force over all primers of a given (short) length. For each,
        # run the self-unzipping decryption and score the result. The correct
        # primer makes the WHOLE message decrypt to English (because a wrong
        # primer corrupts the feedback and the text stays garbled).
        primer_len = primer_len or self.attack_primer_len
        print(f"=== Autokey Cryptanalysis ===")
        print(f"  NOTE: Kasiski/index-of-coincidence DO NOT WORK here -- the")
        print(f"  key never repeats, so there is no period to detect. We must")
        print(f"  attack differently: brute force the short primer ({primer_len}")
        print(f"  letters = {26**primer_len} possibilities) and score the")
        print(f"  self-unzipped plaintext for English-likeness.")
        print("-" * 60)
        best = []
        for combo in product(range(26), repeat=primer_len):
            primer = ''.join(chr(c + ord('A')) for c in combo)
            pt = self.decrypt_message(ciphertext, primer)
            best.append((primer, pt, self._score_english(pt)))
        best.sort(key=lambda x: x[2], reverse=True)
        print(f"  Top {top_n} primers by English score:")
        for i, (pr, pt, sc) in enumerate(best[:top_n]):
            print(f"    {i+1}. primer '{pr}' (score {sc:7.1f}): "
                  f"{pt[:45]}{'...' if len(pt) > 45 else ''}")
        return best[0]

    def show_autokey_state(self):
        print(f"Autokey Decrypt State Information:")
        print(f"  Decryption self-unzips: each recovered letter extends the key")
        print(f"  Primer: {self.primer_clean if self.primer_clean else '(attack mode)'}")
        print(f"  Kasiski/IC attack: does NOT apply (no period)")

    def get_cipher_stats(self):
        return {
            'cipher_name': 'Autokey Decrypt',
            'primer': self.primer_clean if self.primer_clean else '(attack mode)',
            'attack': 'short-primer brute force + English scoring',
            'kasiski_applies': False,
            'type': 'polyalphabetic substitution'}
