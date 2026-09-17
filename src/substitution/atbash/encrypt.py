#!/usr/bin/python3

##--------------------------------------------------------------------\
#   cryptography_examples
#   './cryptography_examples/src/substitution/atbash/encrypt.py'
#   Atbash cipher encryption class
#
#   Atbash is one of the oldest known ciphers: a monoalphabetic substitution
#   that REVERSES the alphabet, mapping A<->Z, B<->Y, C<->X, ... It originated
#   as a Hebrew cipher (the name is from the first/last Hebrew letters: aleph-
#   taw-beth-shin) and appears in the Hebrew Bible (e.g. "Sheshach" in
#   Jeremiah is Atbash for "Babel"). For the Latin alphabet: E(x) = 25 - x.
#
#   It has NO key -- the transformation is fixed -- which makes it trivially
#   breakable but historically and pedagogically important: it is the
#   simplest substitution, and it is its own inverse (an involution).
#   It is also exactly the Affine cipher with a=25, b=25.
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
        # Atbash has no key; SHOW_STEPS is the only option.
        self.show_steps = False
        if opt_df is not None and 'SHOW_STEPS' in opt_df.columns:
            self.show_steps = opt_df['SHOW_STEPS'][0]
        self.initialized = True

    def encrypt_message(self, text):
        # E(x) = 25 - x  (A=0 -> Z=25, B=1 -> Y=24, ...). Self-inverse.
        if self.show_steps:
            print(f"\n=== Atbash Encryption: E(x) = 25 - x (reverse the alphabet) ===")
            print(f"  {'plain':>5} {'x':>3} {'25-x':>5} {'cipher':>7}")
        result = []
        for ch in text:
            if ch.isalpha():
                x = ord(ch.upper()) - ord('A')
                y = 25 - x
                enc = chr(y + ord('A'))
                if ch.islower():
                    enc = enc.lower()
                result.append(enc)
                if self.show_steps:
                    print(f"  {ch:>5} {x:>3} {y:>5} {enc:>7}")
            else:
                result.append(ch)
        ciphertext = ''.join(result)
        if self.show_steps:
            print(f"  Ciphertext: {ciphertext}")
        return ciphertext

    def show_atbash_state(self):
        print(f"Atbash State Information:")
        print(f"  Transformation: E(x) = 25 - x (A<->Z, B<->Y, ...)")
        print(f"  Key: none (fixed substitution)")
        print(f"  Self-inverse (involution): yes")
        print(f"  Equivalent Affine cipher: a=25, b=25")
        print(f"  Initialized: {self.initialized}")

    def get_cipher_stats(self):
        return {
            'cipher_name': 'Atbash',
            'formula': 'E(x) = 25 - x',
            'key': 'none (fixed)',
            'self_inverse': True,
            'equivalent_affine': 'a=25, b=25',
            'type': 'monoalphabetic substitution',
            'initialized': self.initialized}
