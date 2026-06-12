#! /usr/bin/python3

##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/asymmetric/ecdh/decrypt_test.py'
#   Some (mostly) AI generated test cases, for fun.
#
#   This shows the ATTACKER's view: given only the public curve, G, and a
#   public point, recover the private scalar by NAIVE discrete log, then
#   reconstruct the shared secret. Public values are produced by actually
#   running the exchange (encrypt class), so they are real.
#
#   Last update: June 02, 2026
##--------------------------------------------------------------------\

import pandas as pd
from asymmetric.ECDH.encrypt import encrypt
from asymmetric.ECDH.decrypt import decrypt


print("=== ECDH Naive Attack Example ===")
print("(TEACHING CURVE - educational only)")

CURVE = {'A': [2], 'B': [2], 'P': [17], 'GX': [5], 'GY': [1]}

# Build real public material by running exchanges.
print("\n=== CREATING TEST CASES (real exchanges) ===")
test_cases = [
    {'name': 'a=3, b=7',  'priv_a': 3,  'priv_b': 7},
    {'name': 'a=9, b=14', 'priv_a': 9,  'priv_b': 14},
    {'name': 'a=12, b=5', 'priv_a': 12, 'priv_b': 5},
]

for case in test_cases:
    e = encrypt(None, pd.DataFrame({
        **CURVE, 'PRIV_A': [case['priv_a']], 'PRIV_B': [case['priv_b']],
        'SHOW_STEPS': [False]
    }))
    e.run_exchange()
    s = e.get_cipher_stats()
    case['A'] = s['public_A']
    case['B'] = s['public_B']
    case['shared'] = s['shared_secret']
    print(f"  {case['name']}: A={case['A']}, B={case['B']}, "
          f"shared={case['shared']}")

print(f"\n{'='*60}")
print("THE ATTACK: recover a private scalar from a public point")
print('='*60)
print("The attacker has the curve, G, A and B - but NOT a or b.\n")

for case in test_cases:
    print(f"\n--- Attacking case {case['name']} ---")
    attacker = decrypt(None, pd.DataFrame({**CURVE, 'SHOW_STEPS': [False]}))
    attacker.estimate_attack_cost()
    print()
    # Recover Alice's secret from her public point A
    recovered_a = attacker.brute_force_decrypt(case['A'])
    print(f"  Expected a = {case['priv_a']}, "
          f"recovered = {recovered_a}, "
          f"match: {'YES' if recovered_a == case['priv_a'] else 'NO'}")

    # Now reconstruct the shared secret using recovered a and public B
    recovered_shared = attacker.recover_shared_secret(case['A'], case['B'])
    print(f"  Shared secret match: "
          f"{'YES' if recovered_shared == case['shared'] else 'NO'}")

print(f"\n{'='*60}")
print("ECDH NAIVE ATTACK SUMMARY")
print('='*60)
print("""
KEY INSIGHTS:

1. RECOVERING ONE SCALAR BREAKS EVERYTHING:
    - Find a from A = a*G, then compute a*B = the shared secret
    - The attacker now holds the same secret as Alice and Bob

2. THE EASY DIRECTION VS THE HARD DIRECTION:
    - Forward:  a*G is cheap (double-and-add)
    - Backward: recovering a from a*G is the discrete log problem

3. WHY THE NAIVE ATTACK WORKS HERE:
    - Our field is tiny (p=17), so trying every scalar is trivial
    - The number of steps grows with the group ORDER

4. WHY REAL ECDH SURVIVES:
    - A real curve's order is ~2^256
    - Even the best attacks need ~2^128 steps - utterly infeasible

5. WHAT THIS TEACHES:
    - Security can rest on a problem being computationally HARD
    - Key/field SIZE is the dial that turns 'breakable' into 'secure'
    - This is the same lesson RSA teaches, via a different hard problem
""")
