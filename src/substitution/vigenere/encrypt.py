#!/usr/bin/python3

##--------------------------------------------------------------------\
#   cryptography_examples
#   './cryptography_examples/src/substitution/vigenere/encrypt.py'
#   Vigenere cipher encryption class
#
#   The Vigenere cipher is a POLYALPHABETIC substitution cipher: it uses a
#   keyword to apply a DIFFERENT Caesar shift to each successive letter,
#   cycling through the keyword. This is the historical answer to frequency
#   analysis -- by spreading each plaintext letter across several cipher
#   alphabets, it flattens the single-letter frequency signature that breaks
#   the monoalphabetic cipher. It sits between the monoalphabetic cipher and
#   Playfair in the arc: the first cipher that genuinely defeats naive
#   frequency analysis.
#
#   Known for centuries as "le chiffre indechiffrable" (the indecipherable
#   cipher) until Babbage (c. 1854, unpublished) and Kasiski (1863) broke it.
#   The decrypt class implements exactly that break.
#
#   Standardized to match the repo: pandas DataFrame options, SHOW_STEPS,
#   encrypt_message / get_cipher_stats / show_* helpers.
#
#   Author(s): Lauren Linkous  (with Claude AI for structure/commentary)
#   Last update: June 02, 2026
##--------------------------------------------------------------------\

import numpy as np

np.seterr(all='raise')


class encrypt:

    def __init__(self, dictionary=None, opt_df=None, parent=None):

        # Optional parent class
        self.parent = parent

        # Kept for framework compatibility.
        self.original_dictionary = dictionary

        # Unpack the data frame.
        #   KEYWORD       - the repeating key (letters only)
        #   KEEP_SPACES   - whether to preserve non-letters in place
        #   SHOW_STEPS    - step-by-step display
        self.keyword = opt_df['KEYWORD'][0] if 'KEYWORD' in opt_df.columns else 'KEY'
        self.keep_spaces = opt_df['KEEP_SPACES'][0] if 'KEEP_SPACES' in opt_df.columns else True
        self.show_steps = opt_df['SHOW_STEPS'][0] if 'SHOW_STEPS' in opt_df.columns else False

        # Normalize the keyword to uppercase letters only.
        self.key_clean = ''.join(ch for ch in self.keyword.upper() if ch.isalpha())
        if not self.key_clean:
            raise ValueError("Vigenere keyword must contain at least one letter.")

        self.initialized = True


    def _shift_char(self, ch, key_char, decrypt=False):
        # Apply (or undo) a Caesar shift of (key_char - 'A') to one letter.
        shift = ord(key_char) - ord('A')
        if decrypt:
            shift = -shift
        base = ord('A')
        return chr((ord(ch.upper()) - base + shift) % 26 + base)


    def encrypt_message(self, text):
        # Walk the plaintext; for each LETTER, use the next keyword letter
        # (cycling). Non-letters are passed through (and don't advance the
        # key) when keep_spaces is True.
        if self.show_steps:
            print(f"\n=== Vigenere Encryption ===")
            print(f"  Keyword: {self.key_clean}")
            print(f"  Plaintext: {text!r}")
            print(f"  {'plain':>5} {'key':>4} {'shift':>6} {'cipher':>7}")

        result = []
        key_index = 0
        for ch in text:
            if ch.isalpha():
                key_char = self.key_clean[key_index % len(self.key_clean)]
                enc = self._shift_char(ch, key_char)
                # preserve original case
                if ch.islower():
                    enc = enc.lower()
                result.append(enc)
                if self.show_steps:
                    shift = ord(key_char) - ord('A')
                    print(f"  {ch:>5} {key_char:>4} {shift:>6} {enc:>7}")
                key_index += 1
            else:
                if self.keep_spaces:
                    result.append(ch)
                # non-letters do not advance the key index

        ciphertext = ''.join(result)
        if self.show_steps:
            print(f"  Ciphertext: {ciphertext}")
        return ciphertext


    def make_full_key(self, text):
        # Demo helper: show the repeating key stream aligned to the text.
        # This is the classic "key written under the message" visualization.
        key_stream = []
        key_index = 0
        for ch in text:
            if ch.isalpha():
                key_stream.append(self.key_clean[key_index % len(self.key_clean)])
                key_index += 1
            else:
                key_stream.append(' ' if self.keep_spaces else '')
        return ''.join(key_stream)


    def show_vigenere_state(self):
        print(f"Vigenere State Information:")
        print(f"  Keyword: {self.key_clean}")
        print(f"  Key length: {len(self.key_clean)}")
        print(f"  Keep spaces: {self.keep_spaces}")
        print(f"  Initialized: {self.initialized}")


    def get_cipher_stats(self):
        return {
            'cipher_name': 'Vigenere',
            'keyword': self.key_clean,
            'key_length': len(self.key_clean),
            'type': 'polyalphabetic substitution',
            'keep_spaces': self.keep_spaces,
            'initialized': self.initialized}
