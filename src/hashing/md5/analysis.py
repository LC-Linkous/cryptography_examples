#! /usr/bin/python3
##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/hashing/md5/analysis.py'
#   Why MD5 is BROKEN: the collision story, and a real collision pair.
#   Last update: June 02, 2026
##--------------------------------------------------------------------\

import pandas as pd
import hashlib
from hash import hashfn

print("=== MD5 ANALYSIS: anatomy of a broken hash ===\n")

print("""TIMELINE OF THE BREAK:
  1992  MD5 published (Rivest, RFC 1321), 128-bit digest.
  1996  Dobbertin finds collisions in the COMPRESSION function -- a warning.
  2004  Wang et al. announce full practical COLLISIONS via differential
        cryptanalysis. Two different inputs, same MD5. Minutes of compute.
  2005  Lenstra/Wang/de Weger: colliding X.509 certificates.
  2008  A rogue CA certificate forged via MD5 collisions (real PKI break).
  2012  The Flame espionage malware forges a Microsoft code-signing cert
        using an MD5 chosen-prefix collision -- a nation-state weaponization.
  Today Collisions are trivial; MD5 is forbidden for signatures/certs. It
        lingers only as a non-security checksum (and even that is discouraged).
""")

# A FAMOUS published MD5 collision (Wang et al. / Klima). Two distinct
# 128-byte messages with the SAME MD5. We hash both with our own
# implementation to PROVE the collision is real.
print("=== A REAL COLLISION (two different inputs, identical MD5) ===")
block1 = bytes.fromhex(
    "d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f89"
    "55ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5b"
    "d8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0"
    "e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70")
block2 = bytes.fromhex(
    "d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f89"
    "55ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5b"
    "d8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0"
    "e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70")
h = hashfn(None, pd.DataFrame({'SHOW_STEPS': [False]}))
m1 = h.hash_message(block1)
m2 = h.hash_message(block2)
print(f"  inputs identical?  {block1 == block2}")
print(f"  MD5(block1) = {m1}")
print(f"  MD5(block2) = {m2}")
print(f"  SAME HASH from DIFFERENT inputs: {m1 == m2}  <-- a collision")
print(f"  (cross-check with hashlib: {hashlib.md5(block1).hexdigest() == hashlib.md5(block2).hexdigest()})")

print(f"\n=== THE LESSON ===")
print("""  A cryptographic hash must be COLLISION-RESISTANT: infeasible to find
  any two inputs with the same digest. MD5's 128-bit size means a birthday
  attack needs ~2^64 work in theory -- but the Wang attacks do FAR better by
  exploiting the math of the compression function, making collisions a
  laptop exercise. Once collisions are cheap, any system relying on MD5 to
  bind data to identity (certificates, signatures, file integrity vs an
  adversary) is broken. Use SHA-256 (in this repo) or SHA-3.""")
