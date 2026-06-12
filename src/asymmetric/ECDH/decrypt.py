#!/usr/bin/python3

##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/asymmetric/ecdh/decrypt.py'
#   ECDH attacker (TEACHING-SIZED curve) - naive discrete log
#
#   Companion to the symmetric decrypt classes and to RSA's decrypt.py.
#   The attacker is an eavesdropper: they see the public curve, the base
#   point G, and a party's PUBLIC point P = k*G. They do NOT have the
#   private scalar k. Recovering k is the ELLIPTIC-CURVE DISCRETE LOG
#   PROBLEM (ECDLP).
#
#   This file solves it the NAIVE way: keep adding G to itself
#   (1*G, 2*G, 3*G, ...) until the running point equals P. The number of
#   the step IS the private scalar. Works here only because the field is
#   tiny. decrypt_improved.py does it the smart way (baby-step giant-step).
#
#   Once k is recovered, the attacker can compute the shared secret exactly
#   as the legitimate party would - so recovering ONE private scalar breaks
#   the whole exchange.
#
#   ##  WARNING - TEACHING CURVE  ##  see encrypt.py and the README.
#
#   Author(s): Lauren Linkous
#   Last update: June 02, 2026
##--------------------------------------------------------------------\

import numpy as np
import time
from math import isqrt

np.seterr(all='raise')


class decrypt:

    def __init__(self, dictionary=None, opt_df=None, parent=None):

        self.parent = parent
        self.original_dictionary = dictionary

        # Public curve parameters - all known to an attacker.
        self.a = int(opt_df['A'][0]) if 'A' in opt_df.columns else 2
        self.b = int(opt_df['B'][0]) if 'B' in opt_df.columns else 2
        self.p = int(opt_df['P'][0]) if 'P' in opt_df.columns else 17
        gx = int(opt_df['GX'][0]) if 'GX' in opt_df.columns else 5
        gy = int(opt_df['GY'][0]) if 'GY' in opt_df.columns else 1
        self.G = (gx, gy)

        self.show_steps = opt_df['SHOW_STEPS'][0] if 'SHOW_STEPS' in opt_df.columns else False

        # Filled in when an attack recovers a private scalar.
        self.recovered_k = None


    # --- curve arithmetic (identical to the encrypt class) ---

    def inverse_mod(self, k, p):
        if k % p == 0:
            raise ZeroDivisionError("Division by zero in modular inverse.")
        return pow(k % p, p - 2, p)

    def point_add(self, point1, point2):
        if point1 is None:
            return point2
        if point2 is None:
            return point1
        x1, y1 = point1
        x2, y2 = point2
        if x1 == x2 and (y1 + y2) % self.p == 0:
            return None
        if x1 == x2 and y1 == y2:
            numerator = (3 * x1 * x1 + self.a) % self.p
            denominator = self.inverse_mod((2 * y1) % self.p, self.p)
            slope = (numerator * denominator) % self.p
        else:
            numerator = (y2 - y1) % self.p
            denominator = self.inverse_mod((x2 - x1) % self.p, self.p)
            slope = (numerator * denominator) % self.p
        x3 = (slope * slope - x1 - x2) % self.p
        y3 = (slope * (x1 - x3) - y1) % self.p
        return (x3, y3)

    def scalar_mult(self, k, point):
        result = None
        addend = point
        while k:
            if k & 1:
                result = self.point_add(result, addend)
            addend = self.point_add(addend, addend)
            k >>= 1
        return result


    # --- the attack: solve P = k*G for k ---

    def brute_force_decrypt(self, public_point, max_steps=None):
        # Naive ECDLP: add G repeatedly until we hit the target public point.
        # The step count where we match is the private scalar k.

        print(f"=== Naive Discrete-Log Attack ===")
        print(f"  Curve: y^2 = x^3 + {self.a}x + {self.b} (mod {self.p})")
        print(f"  Base point G = {self.G}")
        print(f"  Target public point P = {public_point}")
        print(f"  Strategy: compute 1*G, 2*G, 3*G, ... until it equals P")
        print("-" * 60)

        # The order can't exceed the field size by more than a little
        # (Hasse's theorem), so capping near p is a safe upper bound here.
        limit = max_steps if max_steps is not None else (self.p + 2 * isqrt(self.p) + 1)

        start = time.time()
        current = None  # 0*G = point at infinity
        for k in range(1, limit + 1):
            current = self.point_add(current, self.G)
            if self.show_steps and k <= 20:
                print(f"  {k:2d}*G = {current}")
            if current == public_point:
                elapsed = time.time() - start
                print(f"  RECOVERED private scalar k = {k} "
                      f"in {k} point additions ({elapsed:.6f}s)")
                self.recovered_k = k
                return k
            if current is None:
                # We have looped through the whole subgroup without a match.
                break

        print(f"  No scalar found up to the group order. "
              f"P may not be a multiple of G.")
        return None


    def recover_shared_secret(self, public_point_to_attack, other_public_point):
        # Full break: recover one party's private scalar by discrete log,
        # then use it with the OTHER party's public point to derive the very
        # same shared secret the legitimate parties computed.

        print(f"\n=== Recovering the Shared Secret ===")
        k = self.brute_force_decrypt(public_point_to_attack)
        if k is None:
            return None
        shared = self.scalar_mult(k, other_public_point)
        print(f"  Using recovered k={k} with the other public point "
              f"{other_public_point}:")
        print(f"  Shared secret = {k} * {other_public_point} = {shared}")
        return shared


    def estimate_attack_cost(self):
        # DEMO ONLY. Reports the scale of the discrete-log problem. Naive
        # search is ~order steps; the best general attacks (rho / BSGS) are
        # ~sqrt(order), which is still astronomically large for real curves.
        order_estimate = self.p  # close enough for the teaching curve
        bsgs_estimate = isqrt(order_estimate) + 1
        print(f"=== ECDLP Cost Estimate (field p = {self.p}) ===")
        print(f"  Naive search: about {order_estimate} point additions")
        print(f"  Smart (sqrt) attacks: about {bsgs_estimate} steps")
        print(f"  For a real ~256-bit curve, sqrt(order) ~ 2^128 steps -")
        print(f"  more operations than there are atoms to count them with.")
        return order_estimate


    def show_curve_state(self):
        print(f"ECDH Attack State Information:")
        print(f"  Curve: y^2 = x^3 + {self.a}x + {self.b} (mod {self.p})")
        print(f"  Base point G: {self.G}")
        print(f"  Field size p: {self.p} ({self.p.bit_length()} bits)")
        if self.recovered_k is not None:
            print(f"  [ATTACK SUCCEEDED] recovered private scalar k = {self.recovered_k}")


    def get_cipher_stats(self):
        stats = {
            'cipher_name': 'ECDH Attack (naive ECDLP)',
            'curve': f'y^2 = x^3 + {self.a}x + {self.b} mod {self.p}',
            'base_point_G': self.G,
            'field_prime_p': self.p,
            'field_bits': self.p.bit_length()}
        if self.recovered_k is not None:
            stats['recovered_scalar_k'] = self.recovered_k
        return stats
