#!/usr/bin/python3

##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/asymmetric/ecdh/decrypt_improved.py'
#   ECDH smart attack (TEACHING-SIZED curve) - Baby-Step Giant-Step
#
#   Companion to decrypt.py, in the same spirit as RSA's decrypt_improved:
#   the basic attack solves the discrete log by trying every scalar
#   (~order steps). This file uses BABY-STEP GIANT-STEP (BSGS), which
#   solves it in roughly sqrt(order) steps by trading memory for time.
#
#   BSGS is a meet-in-the-middle method:
#     Write the unknown k as  k = i*m + j   where m = ceil(sqrt(order)).
#     1. BABY STEPS:  build a table of j*G for j = 0..m-1
#     2. GIANT STEPS: compute P - i*(m*G) for i = 0,1,2,...; each is one
#        "giant" stride. When one lands in the baby table, k = i*m + j.
#
#   This is still infeasible against real curves (sqrt of a 256-bit order
#   is ~2^128), but it dramatically beats the naive search on our teaching
#   curve - exactly the naive-vs-smart contrast we drew for RSA factoring.
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


class decrypt_improved:

    def __init__(self, dictionary=None, opt_df=None, parent=None):

        self.parent = parent
        self.original_dictionary = dictionary

        self.a = int(opt_df['A'][0]) if 'A' in opt_df.columns else 2
        self.b = int(opt_df['B'][0]) if 'B' in opt_df.columns else 2
        self.p = int(opt_df['P'][0]) if 'P' in opt_df.columns else 17
        gx = int(opt_df['GX'][0]) if 'GX' in opt_df.columns else 5
        gy = int(opt_df['GY'][0]) if 'GY' in opt_df.columns else 1
        self.G = (gx, gy)

        # The order of the base point (size of the subgroup it generates).
        # The attacker can compute this themselves; we allow setting it for
        # reproducible demos. Defaults to the teaching curve's order of 19.
        self.order = int(opt_df['ORDER'][0]) if 'ORDER' in opt_df.columns else 19

        self.show_steps = opt_df['SHOW_STEPS'][0] if 'SHOW_STEPS' in opt_df.columns else False
        self.recovered_k = None


    # --- curve arithmetic (identical to the encrypt class) ---

    def inverse_mod(self, k, p):
        if k % p == 0:
            raise ZeroDivisionError("Division by zero in modular inverse.")
        return pow(k % p, p - 2, p)

    def point_negate(self, point):
        # -P is (x, -y mod p). Needed to subtract points (P + (-Q)).
        if point is None:
            return None
        x, y = point
        return (x, (-y) % self.p)

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


    # --- the smart attack: baby-step giant-step ---

    def brute_force_decrypt(self, public_point):
        # Solve P = k*G for k using BSGS in ~sqrt(order) steps.

        m = isqrt(self.order) + 1

        print(f"=== Baby-Step Giant-Step Attack ===")
        print(f"  Curve: y^2 = x^3 + {self.a}x + {self.b} (mod {self.p})")
        print(f"  Base point G = {self.G}, subgroup order = {self.order}")
        print(f"  Target public point P = {public_point}")
        print(f"  m = ceil(sqrt(order)) = {m}  (table size and stride)")
        print("-" * 60)

        start = time.time()

        # 1. BABY STEPS: table mapping  j*G -> j   for j = 0..m-1
        baby_table = {}
        current = None  # 0*G
        for j in range(m):
            baby_table[current] = j
            current = self.point_add(current, self.G)
        if self.show_steps:
            print(f"  Built baby-step table with {len(baby_table)} entries")

        # 2. GIANT STEPS: stride of m*G, walking P - i*(m*G)
        m_G = self.scalar_mult(m, self.G)
        neg_mG = self.point_negate(m_G)

        gamma = public_point
        steps = 0
        for i in range(m):
            steps += 1
            if gamma in baby_table:
                j = baby_table[gamma]
                k = (i * m + j) % self.order
                elapsed = time.time() - start
                print(f"  MATCH at giant step i={i}, baby index j={j}")
                print(f"  RECOVERED private scalar k = i*m + j = "
                      f"{i}*{m} + {j} = {k}  ({steps} giant steps, "
                      f"{elapsed:.6f}s)")
                self.recovered_k = k
                return k
            gamma = self.point_add(gamma, neg_mG)

        print(f"  No match found - check the subgroup order.")
        return None


    def recover_shared_secret(self, public_point_to_attack, other_public_point):
        print(f"\n=== Recovering the Shared Secret (BSGS) ===")
        k = self.brute_force_decrypt(public_point_to_attack)
        if k is None:
            return None
        shared = self.scalar_mult(k, other_public_point)
        print(f"  Shared secret = {k} * {other_public_point} = {shared}")
        return shared


    def get_cipher_stats(self):
        m = isqrt(self.order) + 1
        stats = {
            'cipher_name': 'ECDH Attack (BSGS)',
            'curve': f'y^2 = x^3 + {self.a}x + {self.b} mod {self.p}',
            'base_point_G': self.G,
            'subgroup_order': self.order,
            'bsgs_table_size_m': m}
        if self.recovered_k is not None:
            stats['recovered_scalar_k'] = self.recovered_k
        return stats
