#! /usr/bin/python3
##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/hashing/sha1/analysis.py'
#   Why SHA-1 is BROKEN: the SHATTERED story and the migration lesson.
#   Last update: June 02, 2026
##--------------------------------------------------------------------\

import pandas as pd
from hash import hashfn

print("=== SHA-1 ANALYSIS: a hash that limped on too long ===\n")

print("""TIMELINE OF THE BREAK:
  1995  SHA-1 published (FIPS 180-1), 160-bit digest. Became ubiquitous:
        TLS certificates, git, PGP, code signing.
  2005  Wang, Yin, Yu: a theoretical collision attack at ~2^69, well under
        the 2^80 birthday bound. SHA-1 is now known to be mortally wounded;
        NIST begins deprecation. But deployed systems are slow to move.
  2017  SHATTERED (Stevens, Bursztein, Karpman, Albertini, Markov / Google
        + CWI): the FIRST PRACTICAL collision. Two distinct PDF files with
        the same SHA-1, at a cost of ~2^63.1 (~6500 CPU-years + 110 GPU-
        years). Headline proof that "wounded" had become "dead."
  2020  Leurent & Peyrin: a CHOSEN-PREFIX collision (~2^63.4, ~$45k of
        cloud GPU). This is the dangerous kind -- it allows colliding inputs
        with attacker-chosen, meaningful prefixes, threatening PGP identity
        certs. SHA-1 is now actively hazardous, not just theoretically weak.
  Today Retired for security. git has migrated toward SHA-256; browsers and
        CAs reject SHA-1 certificates outright.
""")

print("=== AVALANCHE: SHA-1 still 'looks' random (good hashes can still die) ===")
h = hashfn(None, pd.DataFrame({'SHOW_STEPS': [False]}))
base = "the quick brown fox"
hashes = []
for i, repl in enumerate(["the quick brown fox", "the quick brown box",
                          "the quick brown foy", "the quick brown fox "]):
    d = h.hash_message(repl)
    hashes.append(d)
    print(f"  {repl!r:24} -> {d}")
print("""
  Note the avalanche is excellent -- tiny input changes scramble the output.
  The LESSON: good statistical behavior (avalanche) does NOT imply collision
  resistance. SHA-1 avalanches beautifully and is still broken, because the
  break exploits the algebraic STRUCTURE of the round function, not any
  statistical bias you could see by eye. 'Looks random' is necessary but
  nowhere near sufficient for a cryptographic hash.
""")

print("=== THE MIGRATION LESSON ===")
print("""  SHA-1 survived ~12 years between 'theoretically broken' (2005) and
  'practically broken' (2017), and lingered in systems years beyond that.
  The takeaway for practitioners: migrate when the theoretical cracks appear,
  not when the practical break lands -- because by then attackers have a head
  start and your data may already have been harvested. Crypto-agility (the
  ability to swap primitives quickly) is itself a security property.""")
