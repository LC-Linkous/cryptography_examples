"""Round-trip and known-answer tests for the example classes.

Each test only touches the public API the *_test.py demo scripts already use,
so these double as a compact reference for how to drive each class.
"""
import hashlib
import zlib

import pytest

UPPER = [chr(i) for i in range(65, 91)]


# ---------------------------------------------------------------- substitution

def test_caesar_roundtrip_and_autobreak(load_module, opts):
    enc = load_module('substitution/caesar/encrypt.py').encrypt(UPPER, opts(OFFSET=3, WRAP_SEPARATELY=False))
    enc.create_encryption_dictionary()
    ct = enc.encrypt_message("HELLO WORLD")
    assert ct == "KHOOR ZRUOG"

    dec = load_module('substitution/caesar/decrypt.py').decrypt(UPPER)
    # np.roll(-3) on encrypt (A->D) is undone by np.roll(+3) on decrypt.
    assert dec.decrypt_with_offset(ct, 3) == "HELLO WORLD"
    # The brute-force ranking must now put the real plaintext first.
    best = dec.brute_force_decrypt("WKH TXLFN EURZQ IRA MXPSV RYHU WKH ODCB GRJ")[0]
    assert best[1] == "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG"


def test_atbash_is_an_involution(load_module, opts):
    enc = load_module('substitution/atbash/encrypt.py').encrypt(UPPER, opts(SHOW_STEPS=False))
    once = enc.encrypt_message("ATTACK AT DAWN")
    assert once != "ATTACK AT DAWN"
    assert enc.encrypt_message(once) == "ATTACK AT DAWN"


def test_vigenere_roundtrip(load_module, opts):
    enc = load_module('substitution/vigenere/encrypt.py').encrypt(UPPER, opts(KEYWORD='LEMON', KEEP_SPACES=False))
    dec = load_module('substitution/vigenere/decrypt.py').decrypt(UPPER, opts(KEYWORD='LEMON'))
    ct = enc.encrypt_message("ATTACKATDAWN")
    assert ct == "LXFOPVEFRNHR"          # the Wikipedia worked example
    assert dec.decrypt_message(ct) == "ATTACKATDAWN"


# ------------------------------------------------------------------- stream

def test_otp_xor_roundtrip_and_key_length_rule(load_module, opts):
    enc = load_module('stream/otp/encrypt.py').encrypt(None, opts(MODE='xor'))
    dec = load_module('stream/otp/decrypt.py').decrypt(None, opts(MODE='xor'))
    ct_hex = enc.encrypt_message("perfect secrecy")
    key = enc.get_last_key()
    assert dec.decrypt_message(ct_hex, key) == "perfect secrecy"

    short = load_module('stream/otp/encrypt.py').encrypt(None, opts(MODE='xor', KEY='0a0b'))
    with pytest.raises(ValueError):
        short.encrypt_message("longer than two bytes")


# --------------------------------------------------------------- asymmetric

def test_rsa_roundtrip_with_private_key(load_module, opts):
    enc = load_module('asymmetric/RSA/encrypt.py').encrypt(None, opts(P=61, Q=53, E=17, OUTPUT_FORMAT='LIST'))
    enc.generate_keypair()
    n, d = enc.n, enc.d
    assert n == 3233 and d == 2753   # textbook values for p=61, q=53, e=17
    ct = enc.encrypt_message("HI")
    dec = load_module('asymmetric/RSA/decrypt.py').decrypt(None, opts(N=n, E=17, D=d, INPUT_FORMAT='LIST'))
    assert dec.decrypt_message(ct) == "HI"


# ------------------------------------------------------------------ hashing

@pytest.mark.parametrize("msg", ["", "abc", "The quick brown fox jumps over the lazy dog", "a" * 200])
def test_sha256_matches_hashlib(load_module, opts, msg):
    h = load_module('hashing/sha256/hash.py').hashfn(None, opts(OUTPUT_FORMAT='HEX'))
    assert h.hash_message(msg) == hashlib.sha256(msg.encode()).hexdigest()


@pytest.mark.parametrize("msg", ["", "abc", "message digest", "b" * 150])
def test_md5_and_sha1_match_hashlib(load_module, opts, msg):
    md5 = load_module('hashing/md5/hash.py').hashfn(None, opts())
    sha1 = load_module('hashing/sha1/hash.py').hashfn(None, opts())
    assert md5.hash_message(msg) == hashlib.md5(msg.encode()).hexdigest()
    assert sha1.hash_message(msg) == hashlib.sha1(msg.encode()).hexdigest()


@pytest.mark.parametrize("msg", ["", "abc", "123456789"])
def test_crc32_matches_zlib(load_module, opts, msg):
    h = load_module('hashing/crc32/hash.py').hashfn(None, opts())
    assert h.hash_message(msg) == f"{zlib.crc32(msg.encode()):08x}"
