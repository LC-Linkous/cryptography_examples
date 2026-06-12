#!/usr/bin/python3

##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/grids/playfair/encrypt.py'
#   Playfair cipher encryption class
#
#   The Playfair cipher (Charles Wheatstone, 1854; promoted by Lord
#   Playfair) is a DIGRAPH substitution: it encrypts letters two at a time
#   using a 5x5 key square. Because it substitutes PAIRS rather than single
#   letters, simple single-letter frequency analysis does not break it the
#   way it breaks the monoalphabetic cipher - a nice "next step up" lesson.
#   It lives in the grid section because, like Polybius, it is built on a
#   5x5 key square.
#
#   Standardized to match the other ciphers in this repo: a pandas
#   DataFrame supplies options, SHOW_STEPS toggles the step-by-step
#   display, and the class exposes encrypt_message / get_cipher_stats /
#   show_* helpers.
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

        # Kept for framework compatibility (Playfair works on letters via
        # its key square, not an external dictionary).
        self.original_dictionary = dictionary

        # Unpack the data frame.
        #   KEYWORD     - seeds the 5x5 square
        #   COMBINE     - the two letters sharing a cell (classic is I/J)
        #   PAD         - filler inserted between a doubled pair and at the
        #                 end if the message has odd length
        #   SHOW_STEPS  - step-by-step display
        self.keyword = opt_df['KEYWORD'][0] if 'KEYWORD' in opt_df.columns else 'KEYWORD'
        self.combine = opt_df['COMBINE'][0] if 'COMBINE' in opt_df.columns else 'J'
        self.pad = opt_df['PAD'][0] if 'PAD' in opt_df.columns else 'X'
        self.show_steps = opt_df['SHOW_STEPS'][0] if 'SHOW_STEPS' in opt_df.columns else False

        # The letter that 'combine' maps onto (I/J -> the kept letter is I).
        # We drop self.combine from the alphabet and fold it onto its partner.
        self.kept = 'I' if self.combine.upper() == 'J' else 'A'
        # More generally: keep the alphabet minus the combined letter.
        self.alphabet = self._build_alphabet()

        # Build the 5x5 square and a coordinate lookup.
        self.square = self._build_square()
        self.pos = {self.square[r][c]: (r, c) for r in range(5) for c in range(5)}

        self.initialized = True


    def _build_alphabet(self):
        # 25-letter alphabet: standard A-Z with the combined letter removed.
        drop = self.combine.upper()
        return ''.join(ch for ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if ch != drop)


    def _build_square(self):
        # Fill the 5x5 square with the keyword (de-duplicated) first, then
        # the remaining letters of the alphabet in order.
        seen = []
        seen_set = set()
        source = self.keyword.upper() + self.alphabet
        for ch in source:
            if not ch.isalpha():
                continue
            # Fold the combined letter onto its partner.
            if ch == self.combine.upper():
                ch = self.kept
            if ch not in seen_set and ch in self.alphabet:
                seen_set.add(ch)
                seen.append(ch)
        # Lay the 25 letters into a 5x5 grid.
        square = [seen[i*5:(i+1)*5] for i in range(5)]
        return square


    def _clean_text(self, text):
        # Uppercase, drop non-letters, fold the combined letter.
        out = []
        for ch in text.upper():
            if ch.isalpha():
                out.append(self.kept if ch == self.combine.upper() else ch)
        return ''.join(out)


    def _make_digraphs(self, cleaned):
        # Split into letter pairs. If both letters of a pair are equal,
        # insert the pad between them. If the final pair is a lone letter,
        # append the pad. This is the standard Playfair preprocessing.
        digraphs = []
        i = 0
        while i < len(cleaned):
            a = cleaned[i]
            if i + 1 < len(cleaned):
                b = cleaned[i + 1]
                if a == b:
                    # doubled letter: pair a with the pad, advance by one
                    digraphs.append(a + self.pad)
                    i += 1
                else:
                    digraphs.append(a + b)
                    i += 2
            else:
                # lone trailing letter: pad it
                digraphs.append(a + self.pad)
                i += 1
        return digraphs


    def _encrypt_pair(self, a, b):
        # The three Playfair rules:
        (r1, c1) = self.pos[a]
        (r2, c2) = self.pos[b]
        if r1 == r2:
            # SAME ROW: replace each by the letter to its right (wrap).
            return self.square[r1][(c1 + 1) % 5] + self.square[r2][(c2 + 1) % 5]
        elif c1 == c2:
            # SAME COLUMN: replace each by the letter below (wrap).
            return self.square[(r1 + 1) % 5][c1] + self.square[(r2 + 1) % 5][c2]
        else:
            # RECTANGLE: swap the columns (take the letter in the same row
            # but the other letter's column).
            return self.square[r1][c2] + self.square[r2][c1]


    def encrypt_message(self, text):
        cleaned = self._clean_text(text)
        digraphs = self._make_digraphs(cleaned)

        if self.show_steps:
            print(f"\n=== Playfair Encryption ===")
            self.show_square()
            print(f"  Plaintext : {text!r}")
            print(f"  Cleaned   : {cleaned}")
            print(f"  Digraphs  : {' '.join(digraphs)}")
            print(f"  {'pair':>4} -> {'cipher':>6}   rule")

        result = []
        for pair in digraphs:
            a, b = pair[0], pair[1]
            enc = self._encrypt_pair(a, b)
            result.append(enc)
            if self.show_steps:
                (r1, c1), (r2, c2) = self.pos[a], self.pos[b]
                rule = ("same-row" if r1 == r2 else
                        "same-col" if c1 == c2 else "rectangle")
                print(f"  {pair:>4} -> {enc:>6}   {rule}")

        ciphertext = ''.join(result)
        if self.show_steps:
            print(f"  Ciphertext: {ciphertext}")
        return ciphertext


    def show_square(self):
        print(f"  5x5 key square (keyword '{self.keyword.upper()}', "
              f"{self.combine.upper()} folded onto {self.kept}):")
        for row in self.square:
            print(f"    {' '.join(row)}")


    def show_playfair_state(self):
        print(f"Playfair State Information:")
        print(f"  Keyword: {self.keyword.upper()}")
        print(f"  Combined letters: {self.combine.upper()}/{self.kept}")
        print(f"  Pad letter: {self.pad}")
        print(f"  Initialized: {self.initialized}")
        self.show_square()


    def get_cipher_stats(self):
        return {
            'cipher_name': 'Playfair',
            'keyword': self.keyword.upper(),
            'combine': f"{self.combine.upper()}/{self.kept}",
            'pad': self.pad,
            'square_size': '5x5 (25 letters)',
            'unit': 'digraph (letter pairs)',
            'initialized': self.initialized}
