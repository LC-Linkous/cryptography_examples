#!/usr/bin/python3

##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/substitution/autokey/encrypt.py'
#   Autokey cipher encryption class
#
#   The Autokey cipher (Vigenere, 1586 -- his actual invention, ironically
#   stronger than the "Vigenere cipher" later named after him) fixes the
#   fatal weakness of the repeating-key Vigenere: it does NOT repeat the key.
#   Instead, a short PRIMER keyword starts the key, and then the PLAINTEXT
#   ITSELF continues it:
#       key stream = PRIMER + PLAINTEXT
#       C = (P + K) mod 26
#   Because the key never repeats, there is no period for the index of
#   coincidence or Kasiski examination to find -- the primary attack on
#   Vigenere simply does not apply. (It is still breakable; see decrypt.py.)
#
#   Note: this is the PLAINTEXT-autokey (the historical and stronger form).
#   A ciphertext-autokey variant exists but is weaker and not used here.
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
        # PRIMER is the short starting key; the plaintext extends it.
        self.primer = opt_df['PRIMER'][0] if 'PRIMER' in opt_df.columns else 'KEY'
        self.keep_spaces = opt_df['KEEP_SPACES'][0] if 'KEEP_SPACES' in opt_df.columns else True
        self.show_steps = opt_df['SHOW_STEPS'][0] if 'SHOW_STEPS' in opt_df.columns else False
        self.primer_clean = ''.join(ch for ch in self.primer.upper() if ch.isalpha())
        if not self.primer_clean:
            raise ValueError("Autokey primer must contain at least one letter.")
        self.initialized = True

    def encrypt_message(self, text):
        # Build the key stream as primer + plaintext-letters, then add mod 26.
        plain_letters = [ch.upper() for ch in text if ch.isalpha()]
        key_stream = list(self.primer_clean) + plain_letters  # plaintext autokey
        if self.show_steps:
            print(f"\n=== Autokey Encryption: key = PRIMER + PLAINTEXT ===")
            print(f"  Primer: {self.primer_clean}")
            print(f"  Key stream: {''.join(key_stream[:len(plain_letters)])}")
            print(f"  {'plain':>5} {'P':>3} {'key':>4} {'K':>3} {'cipher':>7}")
        result = []
        li = 0  # index into letters / key stream
        for ch in text:
            if ch.isalpha():
                P = ord(ch.upper()) - ord('A')
                K = ord(key_stream[li]) - ord('A')
                C = (P + K) % 26
                enc = chr(C + ord('A'))
                if ch.islower():
                    enc = enc.lower()
                result.append(enc)
                if self.show_steps:
                    print(f"  {ch:>5} {P:>3} {key_stream[li]:>4} {K:>3} {enc:>7}")
                li += 1
            else:
                if self.keep_spaces:
                    result.append(ch)
        ciphertext = ''.join(result)
        if self.show_steps:
            print(f"  Ciphertext: {ciphertext}")
        return ciphertext

    def show_autokey_state(self):
        print(f"Autokey State Information:")
        print(f"  Key stream: PRIMER + PLAINTEXT (non-repeating)")
        print(f"  Primer: {self.primer_clean}  (length {len(self.primer_clean)})")
        print(f"  Resists Kasiski/IC: yes (no period to find)")
        print(f"  Initialized: {self.initialized}")

    def get_cipher_stats(self):
        return {
            'cipher_name': 'Autokey',
            'primer': self.primer_clean,
            'primer_length': len(self.primer_clean),
            'key_construction': 'primer + plaintext (non-repeating)',
            'resists_kasiski': True,
            'type': 'polyalphabetic substitution',
            'initialized': self.initialized}
