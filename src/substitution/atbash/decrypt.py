#!/usr/bin/python3

##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/substitution/atbash/decrypt.py'
#   Atbash cipher decryption class
#
#   Atbash is an INVOLUTION: applying it twice returns the original, so
#   "decryption" is identical to encryption (E(x) = 25 - x, and 25-(25-x)=x).
#   There is no key to attack and no brute force needed -- decryption IS the
#   cipher applied again. We include the class for repo symmetry and to make
#   the self-inverse property explicit, plus a note on why a keyless cipher
#   offers no security at all.
#
#   Author(s): Lauren Linkous  (with Claude AI for structure/commentary)
#   Last update: June 02, 2026
##--------------------------------------------------------------------\

import numpy as np

np.seterr(all='raise')


class decrypt:

    def __init__(self, dictionary=None, opt_df=None, parent=None):
        self.parent = parent
        self.original_dictionary = dictionary
        self.show_steps = False
        if opt_df is not None and 'SHOW_STEPS' in opt_df.columns:
            self.show_steps = opt_df['SHOW_STEPS'][0]
        self.initialized = True

    def decrypt_message(self, ciphertext):
        # Identical to encryption: Atbash is its own inverse.
        if self.show_steps:
            print(f"\n=== Atbash Decryption (same as encryption: involution) ===")
        result = []
        for ch in ciphertext:
            if ch.isalpha():
                x = ord(ch.upper()) - ord('A')
                y = 25 - x
                dec = chr(y + ord('A'))
                if ch.islower():
                    dec = dec.lower()
                result.append(dec)
            else:
                result.append(ch)
        return ''.join(result)

    def brute_force_decrypt(self, ciphertext):
        # There is nothing to brute force -- no key. "Breaking" Atbash is
        # just applying it once. This is the lesson: a keyless cipher has
        # zero security; anyone who knows the algorithm reads the message.
        print(f"=== Atbash 'Attack' ===")
        print(f"  Atbash has NO KEY. There is nothing to search.")
        print(f"  'Breaking' it = applying the same fixed map again.")
        plaintext = self.decrypt_message(ciphertext)
        print(f"  Recovered instantly: {plaintext[:60]}"
              f"{'...' if len(plaintext) > 60 else ''}")
        return plaintext

    def show_atbash_state(self):
        print(f"Atbash Decrypt State Information:")
        print(f"  Decryption = encryption (self-inverse involution)")
        print(f"  Key: none")

    def get_cipher_stats(self):
        return {
            'cipher_name': 'Atbash Decrypt',
            'method': 'identical to encryption (involution)',
            'key': 'none',
            'security': 'none (keyless)',
            'type': 'monoalphabetic substitution'}
