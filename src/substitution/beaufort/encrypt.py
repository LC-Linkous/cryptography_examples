#!/usr/bin/python3

##--------------------------------------------------------------------\
#   cryptography_examples
#   './cryptography_examples/src/substitution/beaufort/encrypt.py'
#   Beaufort cipher encryption class
#
#   The Beaufort cipher is a polyalphabetic relative of Vigenere, attributed
#   to Sir Francis Beaufort (of wind-scale fame). Where Vigenere ADDS the key
#   (C = P + K), Beaufort SUBTRACTS the plaintext from the key:
#       C = (K - P) mod 26.
#   This has an elegant consequence: Beaufort is RECIPROCAL -- the same
#   operation both encrypts and decrypts, because P = (K - C) mod 26 has the
#   identical form. (This is why the Hagelin M-209 cipher machine, which
#   implemented Beaufort, needed no separate decrypt setting.)
#
#   Do not confuse with the "variant Beaufort" (C = P - K), which is simply
#   Vigenere decryption used as encryption. This is the TRUE Beaufort.
#
#   Author(s): Lauren Linkous  (with Claude AI for structure/commentary)
#   Last update: June 02, 2026
##--------------------------------------------------------------------\

import numpy as np

np.seterr(all='raise')


class encrypt:

    def __init__(self, dictionary=None, opt_df=None, parent=None):
        self.parent = parent
        self.original_dictionary = dictionary
        self.keyword = opt_df['KEYWORD'][0] if 'KEYWORD' in opt_df.columns else 'KEY'
        self.keep_spaces = opt_df['KEEP_SPACES'][0] if 'KEEP_SPACES' in opt_df.columns else True
        self.show_steps = opt_df['SHOW_STEPS'][0] if 'SHOW_STEPS' in opt_df.columns else False
        self.key_clean = ''.join(ch for ch in self.keyword.upper() if ch.isalpha())
        if not self.key_clean:
            raise ValueError("Beaufort keyword must contain at least one letter.")
        self.initialized = True

    def encrypt_message(self, text):
        # C = (K - P) mod 26, key cycling over letters only.
        if self.show_steps:
            print(f"\n=== Beaufort Encryption: C = (K - P) mod 26 ===")
            print(f"  Keyword: {self.key_clean}")
            print(f"  {'plain':>5} {'P':>3} {'key':>4} {'K':>3} {'K-P':>5} {'cipher':>7}")
        result = []
        key_index = 0
        for ch in text:
            if ch.isalpha():
                kc = self.key_clean[key_index % len(self.key_clean)]
                P = ord(ch.upper()) - ord('A')
                K = ord(kc) - ord('A')
                C = (K - P) % 26
                enc = chr(C + ord('A'))
                if ch.islower():
                    enc = enc.lower()
                result.append(enc)
                if self.show_steps:
                    print(f"  {ch:>5} {P:>3} {kc:>4} {K:>3} {C:>5} {enc:>7}")
                key_index += 1
            else:
                if self.keep_spaces:
                    result.append(ch)
        ciphertext = ''.join(result)
        if self.show_steps:
            print(f"  Ciphertext: {ciphertext}")
        return ciphertext

    def show_beaufort_state(self):
        print(f"Beaufort State Information:")
        print(f"  Formula: C = (K - P) mod 26")
        print(f"  Keyword: {self.key_clean}  (length {len(self.key_clean)})")
        print(f"  Reciprocal: yes (encryption = decryption)")
        print(f"  Initialized: {self.initialized}")

    def get_cipher_stats(self):
        return {
            'cipher_name': 'Beaufort',
            'keyword': self.key_clean,
            'key_length': len(self.key_clean),
            'formula': 'C = (K - P) mod 26',
            'reciprocal': True,
            'type': 'polyalphabetic substitution',
            'initialized': self.initialized}
