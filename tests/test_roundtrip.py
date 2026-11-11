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


# --------------------------------------------------------------------- grid

@pytest.mark.parametrize("combine, merged_from, merged_to", [("IJ", "J", "I"), ("UV", "V", "U")])
def test_polybius_5x5_grid_holds_25_letters(load_module, opts, combine, merged_from, merged_to):
    enc = load_module('grid/polybius/encrypt.py').encrypt(None, opts(COMBINE_LETTERS=combine))
    enc.create_cipher_grid()
    cells = [c for row in enc.cipher_grid for c in row]
    assert '' not in cells and len(set(cells)) == 25
    assert merged_to in cells and merged_from not in cells


@pytest.mark.parametrize("kw", [{}, {"KEYWORD": "ZEBRA"}, {"GRID_SIZE": 6}])
def test_polybius_roundtrip_keeps_letters_and_word_breaks(load_module, opts, kw):
    pt = "BIG QUIZ VEXING WORDS"
    enc = load_module('grid/polybius/encrypt.py').encrypt(None, opts(**kw))
    ct = enc.encrypt_message(pt)
    assert '[' not in ct
    assert enc.decrypt_message(ct) == pt

    dec = load_module('grid/polybius/decrypt.py').decrypt(None, opts(**kw))
    assert dec.decrypt_message(ct, kw.get("KEYWORD"), 42) == pt


def test_playfair_wikipedia_example(load_module, opts):
    enc = load_module('grid/playfair/encrypt.py').encrypt(None, opts(KEYWORD='PLAYFAIR EXAMPLE'))
    assert enc.encrypt_message("HIDE THE GOLD IN THE TREE STUMP") == "BMODZBXDNABEKUDMUIXMMOUVIF"


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


# RFC 8439 section 2.4.2: the "sunscreen" known-answer vector. It uses
# counter=1 and a 114-byte message (two blocks), so it also checks that the
# keystream starts at COUNTER and advances one block at a time.
RFC8439_KEY = bytes(range(32))
RFC8439_NONCE = bytes.fromhex("000000000000004a00000000")
RFC8439_PT = ("Ladies and Gentlemen of the class of '99: If I could offer you only one "
              "tip for the future, sunscreen would be it.")
RFC8439_CT = ("6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b"
              "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8"
              "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736"
              "5af90bbf74a35be6b40b8eedf2785e42874d")


def test_chacha20_matches_rfc8439(load_module, opts):
    o = opts(KEY=RFC8439_KEY, NONCE=RFC8439_NONCE, COUNTER=1, OUTPUT_FORMAT='HEX')
    ct = load_module('stream/chacha20/encrypt.py').encrypt(None, o).encrypt_message(RFC8439_PT)
    assert ct.replace(' ', '').lower() == RFC8439_CT

    dec = load_module('stream/chacha20/decrypt.py').decrypt(None, opts(
        KEY=RFC8439_KEY, NONCE=RFC8439_NONCE, COUNTER=1, INPUT_FORMAT='HEX'))
    assert dec.decrypt_message(RFC8439_CT) == RFC8439_PT


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
