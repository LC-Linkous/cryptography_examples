#! /usr/bin/python3
##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/hashing/merkle_damgard/analysis.py'
#   The Merkle-Damgard construction: the security theorem AND the inherited
#   length-extension flaw, demonstrated live.
#   Last update: June 02, 2026
##--------------------------------------------------------------------\

import pandas as pd
from hash import hashfn

print("=== MERKLE-DAMGARD ANALYSIS: the shape of MD5/SHA-1/SHA-256 ===\n")

print("""THE CONSTRUCTION (shared by MD5, SHA-1, SHA-256):
  h_0 = IV
  h_i = f(h_{i-1}, block_i)      <- chain a compression function f
  output = h_k
  with the message LENGTH encoded in the padding (MD strengthening).

THE THEOREM (Merkle & Damgard, 1989):
  If the compression function f is collision-resistant, then the whole hash
  is collision-resistant. This is why hash design reduces to designing a good
  f -- the chaining is 'free' security-wise. It is an elegant, foundational
  result and the reason this construction dominated for 30 years.
""")

h = hashfn(None, pd.DataFrame({'SHOW_STEPS': [False]}))

print("=== THE INHERITED FLAW: LENGTH EXTENSION ===")
print("""  The output IS the final chaining value h_k. So anyone who knows
  H(message) and len(message) can RESUME the hash from h_k and compute
  H(message || padding || extension) WITHOUT knowing the message. This breaks
  the naive MAC H(secret || data), and is the headline reason to prefer SHA-3
  (a sponge, no exposed chaining state) or HMAC.
""")

def pad(msg, bs=4):
    ml = len(msg) * 8; msg = msg + b'\x80'
    while (len(msg) + 8) % bs != 0: msg += b'\x00'
    return msg + (ml & 0xFFFFFFFFFFFFFFFF).to_bytes(8, 'big')

# Attacker knows H(secret) and len(secret), NOT secret itself.
secret = b"TOPSECRET"
public_digest = h.hash_message(secret)
public_len = len(secret)
print(f"  PUBLIC: H(secret) = {public_digest}, len(secret) = {public_len}")
print(f"  (attacker does NOT know secret = {secret!r})")

extension = b"&role=admin"
glue = pad(secret)[public_len:]   # the padding the secret would have gotten
# Attacker forges H(secret || glue || extension) from the digest alone:
forged = h.hash_from_state(public_digest, extension, public_len + len(glue))
# The honest hash of the actual extended message:
honest = h.hash_message(secret + glue + extension)
print(f"\n  attacker appends {extension!r} and forges the digest:")
print(f"    forged  = {forged}")
print(f"    honest  = {honest}")
print(f"    forgery SUCCEEDS (without knowing the secret): {forged == honest}")

print(f"""
=== THE LESSON ===
  Merkle-Damgard's strength (a clean reduction to the compression function)
  comes with a structural weakness (the output exposes the internal state).
  The fixes:
    - HMAC: wrap the keyed hash so the resumable state is never exposed.
    - SHA-3 / sponge: keep a hidden 'capacity' so the output reveals only
      part of the state -- length extension becomes impossible.
  This is why SHA-256 (Merkle-Damgard) is fine for plain hashing but needs
  HMAC for MACs, while SHA-3 can be safely keyed directly.""")
