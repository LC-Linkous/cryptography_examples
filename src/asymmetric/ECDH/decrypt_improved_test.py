#! /usr/bin/python3

##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/asymmetric/ecdh/decrypt_improved_test.py'
#   Some (mostly) AI generated test cases, for fun.
#
#   Compares the NAIVE discrete-log attack (decrypt.py, ~order steps)
#   against BABY-STEP GIANT-STEP (decrypt_improved.py, ~sqrt(order) steps).
#   The step counts tell the story - same naive-vs-smart contrast as the
#   RSA trial-division-vs-Pollard comparison.
#
#   Last update: June 02, 2026
##--------------------------------------------------------------------\

import pandas as pd
from encrypt import encrypt
from decrypt import decrypt
from decrypt_improved import decrypt_improved


print("=== ECDH Attack Comparison: Naive vs Baby-Step Giant-Step ===")
print("(TEACHING CURVE - educational only)")

CURVE = {'A': [2], 'B': [2], 'P': [17], 'GX': [5], 'GY': [1]}
ORDER = 19  # order of G on this curve

# Pick scalars across the range so the larger ones really stress the search.
scalars = [3, 9, 14, 18]

# Build real public points for each scalar.
cases = []
for k in scalars:
    e = encrypt(None, pd.DataFrame({
        **CURVE, 'PRIV_A': [k], 'PRIV_B': [2], 'SHOW_STEPS': [False]
    }))
    e.run_exchange()
    A = e.get_cipher_stats()['public_A']
    cases.append({'k': k, 'A': A})

print()
for case in cases:
    k, A = case['k'], case['A']
    print(f"\n{'#'*70}")
    print(f"# TARGET: private scalar k={k}, public point A={A}")
    print('#'*70)

    print(f"\n>>> NAIVE search (decrypt.py)")
    naive = decrypt(None, pd.DataFrame({**CURVE, 'SHOW_STEPS': [False]}))
    r_naive = naive.brute_force_decrypt(A)

    print(f"\n>>> SMART baby-step giant-step (decrypt_improved.py)")
    bsgs = decrypt_improved(None, pd.DataFrame({
        **CURVE, 'ORDER': [ORDER], 'SHOW_STEPS': [False]
    }))
    r_bsgs = bsgs.brute_force_decrypt(A)

    ok = (r_naive == r_bsgs == k)
    print(f"\n  Both recovered k={k}: {ok}")

print(f"\n{'='*60}")
print("ECDH SMART-ATTACK SUMMARY")
print('='*60)
print("""
WHAT THE COMPARISON SHOWS:

1. BOTH methods solve our tiny curve - the question is HOW MANY STEPS.

2. NAIVE SEARCH:
    - Walks 1*G, 2*G, 3*G, ... so recovering k costs about k additions
    - In the worst case that is ~ the full group ORDER

3. BABY-STEP GIANT-STEP:
    - Trades memory for time: build a sqrt(order)-size table, then stride
    - Recovers k in about sqrt(order) steps regardless of how big k is
    - Watch the giant-step index: large k still resolves in a few strides

4. THE BIG PICTURE:
    - BSGS (and Pollard's rho for EC) are the BEST general attacks known
    - Even so they need ~sqrt(order) ~ 2^128 steps on a real 256-bit curve
    - That gap between sqrt(order) and 'feasible' is the security margin

GROUP DISCUSSION PROMPTS:
    - Why does BSGS find large k in the same effort as small k?
    - How does the table size trade off against the number of giant steps?
    - If a curve's order had a small factor, how might that help an attacker?
""")
