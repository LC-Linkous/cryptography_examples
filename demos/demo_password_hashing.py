#!/usr/bin/python3
"""
demo_password_hashing.py -- Why storing a plain hash of a password is not enough.

The README's hashing section explains that servers store a hash of a password
rather than the password itself. This demo shows why a plain fast hash is still
weak once a database leaks, and what the two standard fixes achieve.

  Act 1  Unsalted SHA-256  -- one lookup table matches many users at once
  Act 2  Salted SHA-256    -- a per-user salt defeats shared/precomputed tables
  Act 3  Slow KDF (PBKDF2) -- a tunable work factor makes guessing expensive

Everything here uses only the standard library (hashlib). The "leaked database"
and "wordlist" are tiny and made up for illustration.

Run:  python demo_password_hashing.py
"""
import hashlib
import os
import time

# A tiny attacker wordlist. Real ones have hundreds of millions of entries.
COMMON_PASSWORDS = [
    "123456", "password", "qwerty", "letmein", "dragon", "monkey",
    "football", "iloveyou", "admin", "welcome", "sunshine", "princess",
    "trustno1", "hunter2", "corvette",
]

# The accounts in our pretend leaked database. Note the duplicate password:
# two different people both chose "password".
ACCOUNTS = [
    ("alice", "password"),
    ("bob", "hunter2"),
    ("carol", "password"),
    ("dave", "corvette"),
]


def sha256_hex(s):
    return hashlib.sha256(s.encode()).hexdigest()


# --------------------------------------------------------------------- Act 1
def act1_unsalted():
    print("=" * 64)
    print("ACT 1: Unsalted SHA-256")
    print("=" * 64)

    # The server stored just sha256(password).
    db = [(user, sha256_hex(pw)) for user, pw in ACCOUNTS]
    print("Leaked table (user -> stored hash):")
    for user, h in db:
        print(f"  {user:6} {h}")

    # Problem 1: equal passwords produce equal hashes. The attacker sees
    # alice and carol share a hash before cracking anything.
    print("\nObservation: alice and carol have the SAME hash, so the attacker")
    print("knows they share a password without breaking it.")

    # Problem 2: the attacker precomputes sha256 of the wordlist ONCE and
    # matches it against every user for free.
    table = {sha256_hex(w): w for w in COMMON_PASSWORDS}
    cracked = [(user, table[h]) for user, h in db if h in table]
    print("\nPrecompute sha256 of the wordlist once, then look up every user:")
    for user, pw in cracked:
        print(f"  CRACKED {user:6} -> {pw}")
    print(f"  {len(cracked)}/{len(db)} accounts recovered from one table.")


# --------------------------------------------------------------------- Act 2
def act2_salted():
    print("\n" + "=" * 64)
    print("ACT 2: Salted SHA-256")
    print("=" * 64)

    # Each account gets its own random salt, stored alongside the hash.
    db = []
    for user, pw in ACCOUNTS:
        salt = os.urandom(8)
        h = hashlib.sha256(salt + pw.encode()).hexdigest()
        db.append((user, salt, h))

    print("Leaked table (user -> salt -> stored hash):")
    for user, salt, h in db:
        print(f"  {user:6} {salt.hex()}  {h}")
    print("\nObservation: alice and carol now have DIFFERENT hashes despite the")
    print("same password, because their salts differ.")

    # A precomputed table no longer works: the attacker must redo the wordlist
    # for each user's salt. Still possible here (fast hash, tiny list), but the
    # shared/precomputed shortcut is gone.
    total_guesses = 0
    cracked = []
    for user, salt, h in db:
        for w in COMMON_PASSWORDS:
            total_guesses += 1
            if hashlib.sha256(salt + w.encode()).hexdigest() == h:
                cracked.append((user, w))
                break
    print("\nThe attacker must re-hash the wordlist against each salt:")
    for user, pw in cracked:
        print(f"  CRACKED {user:6} -> {pw}")
    print(f"  {total_guesses} hash operations needed (vs {len(COMMON_PASSWORDS)} with one table).")
    print("  Salting removes the precomputation shortcut; it does NOT make a")
    print("  fast hash slow. That is Act 3.")


# --------------------------------------------------------------------- Act 3
def act3_slow_kdf():
    print("\n" + "=" * 64)
    print("ACT 3: Salt + a deliberately slow KDF (PBKDF2)")
    print("=" * 64)

    def pbkdf2(pw, salt, iterations):
        return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, iterations)

    # Measure how the per-guess cost scales with the work factor.
    salt = os.urandom(16)
    print("Cost of ONE password guess as the iteration count rises:")
    for iters in (1_000, 50_000, 200_000):
        start = time.perf_counter()
        pbkdf2("corvette", salt, iters)
        dt = time.perf_counter() - start
        print(f"  {iters:>8,} iterations : {dt * 1000:7.2f} ms/guess"
              f"  ->  {dt * len(COMMON_PASSWORDS):6.2f}s for this wordlist")

    print("\nThe legitimate server pays this cost once per login and never")
    print("notices. An attacker testing billions of guesses pays it billions")
    print("of times. That asymmetry is the whole point of a KDF.")
    print("\nReal systems use scrypt, bcrypt, or Argon2 (memory-hard, so custom")
    print("hardware helps the attacker less). PBKDF2 is shown here because it")
    print("ships in Python's hashlib with no extra install.")


if __name__ == "__main__":
    act1_unsalted()
    act2_salted()
    act3_slow_kdf()
    print("\n" + "=" * 64)
    print("Summary: hash -> salt -> slow.")
    print("  hashing alone  : equal passwords leak; one table cracks many users")
    print("  + salt         : kills precomputed/shared tables")
    print("  + slow KDF     : makes each of the attacker's guesses expensive")
    print("=" * 64)
