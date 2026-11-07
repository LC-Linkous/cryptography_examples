#!/usr/bin/python3
"""
demo_hybrid_encryption.py -- How real systems actually combine the two worlds.

The README introduces asymmetric crypto (RSA, ECDH) and symmetric crypto
(stream/block ciphers) as separate families, and mentions "hybrid cryptosystems"
as beyond the introduction. This is that missing worked example -- and it ties
together three things the repo already teaches:

  * RSA (asymmetric)        -- used ONLY to move a small key
  * a stream cipher (XOR)   -- used to encrypt the actual (large) message
  * a hash (SHA-256, HMAC)  -- used to detect tampering

Why hybrid? Asymmetric crypto is slow and size-limited (RSA can only encrypt a
number smaller than n). Symmetric crypto is fast and handles any length but
needs a shared key. Hybrid gets both: encrypt the message with a fresh random
symmetric key, then encrypt just that little key with the recipient's RSA
public key. This is essentially what TLS, PGP, and age do.

This uses toy RSA (small primes, no padding) to stay readable and self-contained
-- the structure is real, the parameters are not secure. Standard library only.

Run:  python demo_hybrid_encryption.py
"""
import hashlib
import hmac
import os
from math import gcd


# ===================================================================== toy RSA
def is_prime(n, rounds=40):
    # Miller-Rabin. Trial division would be hopeless on the ~128-bit primes
    # this demo uses (it would need ~2**64 steps); Miller-Rabin tests one in
    # a fraction of a millisecond.
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = 2 + int.from_bytes(os.urandom(8), "big") % (n - 3)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def modinv(a, m):
    # Extended Euclid
    g, x, _ = _egcd(a, m)
    if g != 1:
        raise ValueError("no modular inverse")
    return x % m


def _egcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x, y = _egcd(b, a % b)
    return g, y, x - (a // b) * y


def rsa_keygen(p, q, e=65537):
    assert is_prime(p) and is_prime(q) and p != q
    n = p * q
    phi = (p - 1) * (q - 1)
    if gcd(e, phi) != 1:
        # Fall back to a small valid e for the tiny-prime case.
        e = next(c for c in range(3, phi, 2) if gcd(c, phi) == 1)
    d = modinv(e, phi)
    return (e, n), (d, n)


def rsa_encrypt_int(m, pub):
    e, n = pub
    assert m < n, "message integer must be smaller than modulus n"
    return pow(m, e, n)


def rsa_decrypt_int(c, priv):
    d, n = priv
    return pow(c, d, n)


# ============================================================ symmetric layer
def keystream(key, nonce, length):
    """A simple counter-mode keystream from SHA-256. Stands in for a real
    stream cipher / block-cipher-in-CTR-mode. key and nonce are bytes."""
    out = bytearray()
    counter = 0
    while len(out) < length:
        block = hashlib.sha256(key + nonce + counter.to_bytes(8, "big")).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:length])


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def mac(key, *parts):
    """Authentication tag over everything, so tampering is detectable."""
    h = hmac.new(key, digestmod=hashlib.sha256)
    for p in parts:
        h.update(len(p).to_bytes(8, "big"))
        h.update(p)
    return h.digest()


# =================================================================== the flow
def seal(message, recipient_pub):
    """Encrypt `message` (bytes) for a recipient, given their RSA public key."""
    # 1. Fresh random symmetric key material for THIS message only.
    sym_key = os.urandom(32)
    nonce = os.urandom(16)

    # 2. Encrypt the (large) message symmetrically -- fast, any length.
    ct = xor(message, keystream(sym_key, nonce, len(message)))

    # 3. Authenticate. A separate MAC key is derived from the symmetric key.
    mac_key = hashlib.sha256(b"mac" + sym_key).digest()
    tag = mac(mac_key, nonce, ct)

    # 4. Encrypt ONLY the little symmetric key with the recipient's RSA key.
    #    (Real systems encrypt the key bytes with OAEP padding; toy RSA here
    #    moves it as a single integer, which fits because n is large enough.)
    _, n = recipient_pub
    assert int.from_bytes(sym_key, "big") < n, \
        "toy modulus too small to wrap a 256-bit key; use larger primes"
    wrapped_key = rsa_encrypt_int(int.from_bytes(sym_key, "big"), recipient_pub)

    return {"wrapped_key": wrapped_key, "nonce": nonce, "ct": ct, "tag": tag}


def unseal(envelope, recipient_priv):
    # 1. Recover the symmetric key with the RSA PRIVATE key.
    sym_int = rsa_decrypt_int(envelope["wrapped_key"], recipient_priv)
    sym_key = sym_int.to_bytes(32, "big")

    # 2. Verify the MAC BEFORE decrypting (authenticate, then decrypt).
    mac_key = hashlib.sha256(b"mac" + sym_key).digest()
    expected = mac(mac_key, envelope["nonce"], envelope["ct"])
    if not hmac.compare_digest(expected, envelope["tag"]):
        raise ValueError("MAC check failed -- message was tampered with or key is wrong")

    # 3. Decrypt the message symmetrically.
    return xor(envelope["ct"], keystream(sym_key, envelope["nonce"], len(envelope["ct"])))


# ========================================================================= main
if __name__ == "__main__":
    print("Generating recipient RSA keypair (large-ish toy primes)...")
    # Each prime is ~160 bits so n > 2**256 and a 32-byte key fits as one
    # integer. These are generated fresh with Miller-Rabin each run.
    def random_prime(bits):
        while True:
            cand = int.from_bytes(os.urandom(bits // 8), "big") | (1 << (bits - 1)) | 1
            if is_prime(cand):
                return cand
    p = random_prime(160)
    q = random_prime(160)
    pub, priv = rsa_keygen(p, q)
    print(f"  public modulus n is {pub[1].bit_length()} bits\n")

    message = ("Meet at the old bridge at noon. Bring the second half of the "
               "ledger. -- This whole sentence is far too long to encrypt with "
               "RSA directly, which is exactly why we use a hybrid scheme.").encode()

    print(f"Plaintext ({len(message)} bytes):\n  {message.decode()}\n")

    env = seal(message, pub)
    print("Envelope on the wire:")
    print(f"  wrapped_key (RSA'd) : {str(env['wrapped_key'])[:48]}...")
    print(f"  nonce               : {env['nonce'].hex()}")
    print(f"  ciphertext ({len(env['ct'])} B)   : {env['ct'][:24].hex()}...")
    print(f"  auth tag            : {env['tag'].hex()[:32]}...\n")

    recovered = unseal(env, priv)
    print("Recipient decrypts with the RSA private key:")
    print(f"  {recovered.decode()}")
    assert recovered == message
    print("  round trip OK\n")

    print("Now an attacker flips one byte of the ciphertext in transit:")
    tampered = dict(env)
    tampered["ct"] = bytes([env["ct"][0] ^ 0x01]) + env["ct"][1:]
    try:
        unseal(tampered, priv)
    except ValueError as exc:
        print(f"  rejected: {exc}")

    print("\nWhat this demonstrates:")
    print("  * RSA moved a 32-byte key, not the message -- that is all it is for.")
    print("  * The symmetric layer did the heavy lifting on arbitrary-length data.")
    print("  * The MAC turned 'confidential' into 'confidential AND tamper-evident'.")
    print("  * This is the shape of TLS/PGP/age: wrap a fresh key, bulk-encrypt,")
    print("    authenticate. Textbook RSA and a SHA-256 keystream stand in for")
    print("    the production primitives, but the assembly is the real thing.")
