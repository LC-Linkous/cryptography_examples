#!/usr/bin/python3

##--------------------------------------------------------------------\
#   cryptography_examples
#   './cryptography_examples/src/asymmetric/rsa/decrypt_improved.py'
#   RSA "smart attack" class (TEXTBOOK RSA - educational only)
#
#   Companion to decrypt.py, in the same spirit as the monoalphabetic and
#   block-cipher 'decrypt_improved' files: the basic decrypt.py factors n
#   by NAIVE trial division. This file factors n with smarter methods and
#   lets students compare the effort.
#
#   Two classic methods are included:
#     * Fermat's method - lightning fast WHEN p and q are close together.
#       This doubles as a security lesson: primes that are too near each
#       other make RSA trivially breakable regardless of key size.
#     * Pollard's rho - a general-purpose factoring method that beats
#       trial division badly on larger moduli.
#
#   Neither of these breaks REAL RSA (2048-bit n with well-chosen primes).
#   They break our small teaching moduli, and Fermat breaks any modulus
#   whose primes were chosen carelessly. That contrast is the point.
#
#   ##  WARNING - TEXTBOOK RSA  ##  see encrypt.py and the README.
#
#   Author(s): Lauren Linkous
#   Last update: June 02, 2026
##--------------------------------------------------------------------\

import numpy as np
import time
from math import gcd, isqrt

np.seterr(all='raise')


class decrypt_improved:

    def __init__(self, dictionary=None, opt_df=None, parent=None):

        self.parent = parent
        self.original_dictionary = dictionary

        # Attacker's view: public key (e, n) only.
        self.n = int(opt_df['N'][0]) if 'N' in opt_df.columns else None
        self.e = int(opt_df['E'][0]) if 'E' in opt_df.columns else 17
        self.input_format = opt_df['INPUT_FORMAT'][0] if 'INPUT_FORMAT' in opt_df.columns else 'INT'
        self.show_steps = opt_df['SHOW_STEPS'][0] if 'SHOW_STEPS' in opt_df.columns else False
        # Which smart method to use: 'FERMAT' or 'POLLARD'
        self.method = opt_df['METHOD'][0] if 'METHOD' in opt_df.columns else 'POLLARD'

        self.recovered_p = None
        self.recovered_q = None
        self.recovered_d = None


    def parse_ciphertext(self, ciphertext):
        if isinstance(ciphertext, list):
            return [int(c) for c in ciphertext]
        if self.input_format == 'HEX':
            return [int(tok, 16) for tok in ciphertext.split()]
        return [int(tok) for tok in ciphertext.split()]


    def mod_inverse(self, a, m):
        old_r, r = a, m
        old_s, s = 1, 0
        while r != 0:
            quotient = old_r // r
            old_r, r = r, old_r - quotient * r
            old_s, s = s, old_s - quotient * s
        if old_r != 1:
            raise ValueError(f"No modular inverse for {a} mod {m}.")
        return old_s % m


    def decrypt_message(self, ciphertext, d, n):
        # Same legitimate decryption as decrypt.py, used after the attack
        # has rebuilt d.
        cipher_ints = self.parse_ciphertext(ciphertext)
        return ''.join(chr(pow(c, d, n)) for c in cipher_ints)


    # -----------------------------------------------------------------\
    #   SMART FACTORING METHOD 1: FERMAT
    # -----------------------------------------------------------------/

    def fermat_factor(self, n, max_iterations=10_000_000):
        # Fermat's method: write n = a^2 - b^2 = (a-b)(a+b).
        # Start a at ceil(sqrt(n)) and step up until a^2 - n is a perfect
        # square. Converges almost instantly when p and q are CLOSE.
        # (The math here is the textbook Fermat method; Claude AI helped
        #  tidy the perfect-square check.)

        a = isqrt(n)
        if a * a < n:
            a += 1

        iterations = 0
        while iterations < max_iterations:
            iterations += 1
            b2 = a * a - n
            b = isqrt(b2)
            if b * b == b2:
                # Found it: p = a - b, q = a + b
                p = a - b
                q = a + b
                return p, q, iterations
            a += 1

        return None, None, iterations


    # -----------------------------------------------------------------\
    #   SMART FACTORING METHOD 2: POLLARD'S RHO
    # -----------------------------------------------------------------/

    def pollard_rho(self, n, max_iterations=10_000_000):
        # Pollard's rho: a probabilistic method that finds a factor far
        # faster than trial division for composite n. Uses the Floyd
        # cycle-finding idea on f(x) = (x^2 + 1) mod n.

        if n % 2 == 0:
            return 2, n // 2, 1

        x = 2
        y = 2
        d = 1
        iterations = 0

        def f(val):
            return (val * val + 1) % n

        while d == 1 and iterations < max_iterations:
            iterations += 1
            x = f(x)          # tortoise moves one step
            y = f(f(y))       # hare moves two steps
            d = gcd(abs(x - y), n)

        if d != 1 and d != n:
            return d, n // d, iterations

        return None, None, iterations


    # -----------------------------------------------------------------\
    #   THE ATTACK
    # -----------------------------------------------------------------/

    def brute_force_decrypt(self, ciphertext, n=None, e=None):
        # Smart-factoring attack. Picks the configured method, factors n,
        # rebuilds the private key, and decrypts. Compare the iteration
        # count printed here against the trial-division count from decrypt.py.

        actual_n = n if n is not None else self.n
        actual_e = e if e is not None else self.e
        if actual_n is None:
            raise ValueError("Need the public modulus n to attempt factoring.")

        print(f"=== Smart Attack: factoring n = {actual_n} ===")
        print(f"  Public key in hand: (e={actual_e}, n={actual_n})")
        print(f"  Modulus size: {actual_n.bit_length()} bits")
        print(f"  Method: {self.method}")
        print("-" * 60)

        start = time.time()
        if self.method == 'FERMAT':
            p, q, iterations = self.fermat_factor(actual_n)
            unit = "Fermat iterations (a-steps)"
        else:
            p, q, iterations = self.pollard_rho(actual_n)
            unit = "Pollard rho iterations"
        elapsed = time.time() - start

        if p is None:
            print(f"  Method did not find a factor in {iterations:,} {unit}.")
            return "Attack failed - try the other method or more iterations"

        print(f"  FACTORED after {iterations:,} {unit} in {elapsed:.4f}s")
        print(f"  Recovered primes: p = {p}, q = {q}")

        recovered_phi = (p - 1) * (q - 1)
        if gcd(actual_e, recovered_phi) != 1:
            print(f"  Recovered phi not coprime with e - aborting.")
            return "Attack failed - key reconstruction error"

        recovered_d = self.mod_inverse(actual_e, recovered_phi)
        self.recovered_p, self.recovered_q, self.recovered_d = p, q, recovered_d

        print(f"  Rebuilt PRIVATE exponent d = {recovered_d}")
        print("-" * 60)

        recovered_message = self.decrypt_message(ciphertext, recovered_d, actual_n)
        print(f"  RECOVERED MESSAGE: '{recovered_message}'")
        return recovered_message


    def get_cipher_stats(self):
        stats = {
            'cipher_name': f'RSA Smart Attack ({self.method})',
            'modulus_n': self.n,
            'modulus_bits': self.n.bit_length() if self.n else None,
            'public_exponent_e': self.e,
            'method': self.method,
            'input_format': self.input_format}
        if self.recovered_d is not None:
            stats['attack_recovered_p'] = self.recovered_p
            stats['attack_recovered_q'] = self.recovered_q
            stats['attack_recovered_d'] = self.recovered_d
        return stats
