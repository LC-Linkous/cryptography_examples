#! /usr/bin/python3
##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/hashing/crc32/analysis.py'
#   Why CRC32 is NOT a cryptographic hash: linearity and trivial forgery.
#   Last update: June 02, 2026
##--------------------------------------------------------------------\

import pandas as pd
from hash import hashfn

print("=== CRC32 ANALYSIS: a checksum is not a hash ===\n")
h = hashfn(None, pd.DataFrame({'SHOW_STEPS': [False]}))

print("""WHAT CRC32 IS FOR:
  Detecting ACCIDENTAL, random errors -- a bit flipped by line noise or a
  bad disk sector. At that job it is excellent and fast, which is why it is
  in Ethernet, ZIP, PNG, and gzip. It guarantees that random single-bit and
  short burst errors are caught. That is a RELIABILITY tool, not a SECURITY
  tool.
""")

print("=== FLAW 1: CRC32 IS LINEAR over GF(2) ===")
linear, ca, cb, cx, c0 = h.demonstrate_linearity("ATTACK AT DAWN", "0000000000abcd")
print(f"  CRC(a) = {ca:08x}")
print(f"  CRC(b) = {cb:08x}")
print(f"  CRC(a XOR b)          = {cx:08x}")
print(f"  CRC(a) XOR CRC(b) XOR CRC(0) = {ca ^ cb ^ c0:08x}")
print(f"  Linear relation holds: {linear}")
print("""  A cryptographic hash must be HIGHLY NONLINEAR. CRC's linearity means
  changes to the message map predictably onto changes in the checksum --
  the attacker can do algebra on it.
""")

print("=== FLAW 2: TRIVIAL FORGERY (no preimage/collision resistance) ===")
msg = b"Pay Alice $10"
crc = h.hash_message(msg)
print(f"  original message : {msg!r}  CRC = {crc}")
# An attacker changes the message and simply RECOMPUTES the CRC -- there is
# no secret, so the checksum offers no protection against deliberate change.
forged = b"Pay Alice $90"
forged_crc = h.hash_message(forged)
print(f"  tampered message : {forged!r}  CRC = {forged_crc}")
print(f"  The attacker just recomputes the CRC for the new message. With no")
print(f"  key and no one-wayness, the checksum 'protects' nothing against an")
print(f"  adversary. (For random NOISE it would have flagged the change --")
print(f"  but a deliberate attacker is not random noise.)")
print("""
=== THE LESSON ===
  CRC32: detects accident, not malice. No key, linear, reversible,
  collisions findable by hand. It is the CONTROL CASE for what a
  cryptographic hash must NOT be. Whenever you see CRC (or any checksum)
  guarding against tampering rather than noise, that is a security bug. For
  integrity against an adversary, use a cryptographic hash (SHA-256) or,
  when authenticity is needed, an HMAC.""")
