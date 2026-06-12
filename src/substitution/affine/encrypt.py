#!/usr/bin/python3

##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/substitution/affine/encrypt.py'
#   Affine cipher encryption class
#
#   The Affine cipher generalizes the Caesar cipher with a multiply AND an
#   add: E(x) = (a*x + b) mod 26, where x is a letter's index (A=0..Z=25).
#   Caesar is the special case a=1. For the map to be invertible, 'a' must
#   be coprime with 26 (gcd(a,26)=1), so a in {1,3,5,7,9,11,15,17,19,21,23,25}
#   -- 12 valid multipliers x 26 additive shifts = 312 keys (311 nontrivial).
#   Decryption needs the modular inverse of a: x = a^-1 (y - b) mod 26.
#
#   It is a nice mathematical step up from Caesar (introduces modular
#   inverses and the coprimality requirement) while remaining a
#   monoalphabetic substitution -- so it still falls to frequency analysis.
#
#   Author(s): Lauren Linkous  (with Claude AI for structure/commentary)
#   Last update: June 02, 2026
##--------------------------------------------------------------------\

import numpy as np
from math import gcd

np.seterr(all='raise')


class encrypt:

    def __init__(self, dictionary=None, opt_df=None, parent=None):
        self.parent = parent
        self.original_dictionary = dictionary

        # A = multiplicative key (must be coprime with 26), B = additive key.
        self.a = int(opt_df['A'][0]) if 'A' in opt_df.columns else 5
        self.b = int(opt_df['B'][0]) if 'B' in opt_df.columns else 8
        self.show_steps = opt_df['SHOW_STEPS'][0] if 'SHOW_STEPS' in opt_df.columns else False

        self.m = 26
        if gcd(self.a, self.m) != 1:
            raise ValueError(
                f"A={self.a} is not coprime with 26, so the cipher is not "
                f"invertible. Valid A: 1,3,5,7,9,11,15,17,19,21,23,25.")
        self.initialized = True

    def encrypt_message(self, text):
        if self.show_steps:
            print(f"\n=== Affine Encryption: E(x) = ({self.a}*x + {self.b}) mod 26 ===")
            print(f"  {'plain':>5} {'x':>3} {'a*x+b':>7} {'cipher':>7}")
        result = []
        for ch in text:
            if ch.isalpha():
                x = ord(ch.upper()) - ord('A')
                y = (self.a * x + self.b) % self.m
                enc = chr(y + ord('A'))
                if ch.islower():
                    enc = enc.lower()
                result.append(enc)
                if self.show_steps:
                    print(f"  {ch:>5} {x:>3} {self.a*x+self.b:>7} {enc:>7}")
            else:
                result.append(ch)
        ciphertext = ''.join(result)
        if self.show_steps:
            print(f"  Ciphertext: {ciphertext}")
        return ciphertext

    def show_affine_state(self):
        print(f"Affine State Information:")
        print(f"  E(x) = ({self.a}*x + {self.b}) mod 26")
        print(f"  Multiplicative key a = {self.a} (coprime with 26: {gcd(self.a,26)==1})")
        print(f"  Additive key b = {self.b}")
        print(f"  Initialized: {self.initialized}")

    def get_cipher_stats(self):
        return {
            'cipher_name': 'Affine',
            'multiplicative_key_a': self.a,
            'additive_key_b': self.b,
            'formula': f'E(x) = ({self.a}x + {self.b}) mod 26',
            'total_keys': '312 (12 valid a x 26 b)',
            'type': 'monoalphabetic substitution',
            'initialized': self.initialized}
