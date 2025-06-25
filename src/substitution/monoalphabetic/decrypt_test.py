#!/usr/bin/python3

##--------------------------------------------------------------------\
#   encryption_examples  
#   './encryption_examples/src/substitution/monoalphabetic/decrypt_test.py'
#   Improved Monoalphabetic cipher decryption class
#   
#   Author: Lauren Linkous
#   Date: June 23, 2025
##--------------------------------------------------------------------\

from decrypt import decrypt

print("=== Improved Monoalphabetic Cipher Brute Force Decryptor ===\n")

# Create brute force decryptor
decryptor = decrypt()

# Test with the same encrypted monoalphabetic messages

test_cases = [
    # "HELLO WORLD" -> "DLROW OLLEH" with alphabet backwards (A->Z, B->Y, etc.)
    ("YMWEK EMMLB", "Expected: HELLO WORLD (backwards alphabet)"),
    
    # "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG" with backwards alphabet substitution
    ("ZBL RUXAC QWEKD JEO FUPVS EHLW ZBL MIGT YEN", "Expected: THE QUICK BROWN FOX..."),
    
    # "ATTACK AT DAWN" - classic cryptography message
    ("IZZIAC IZ YIKD", "Expected: ATTACK AT DAWN"),
    
    # "FREQUENCY ANALYSIS IS THE KEY TO SUCCESS". Note that the random number generator
    # did NOT mix the 'S's. This happens sometimes!
    ("JWLRULDAT IDIMTSXS XS ZBL CLT ZE SUAALSS", "Expected: FREQUENCY ANALYSIS..."),
    
    # Long text test - "IN CRYPTOGRAPHY A SUBSTITUTION CIPHER IS A METHOD OF ENCRYPTING IN WHICH 
    # UNITS OF PLAINTEXT ARE REPLACED WITH THE CIPHERTEXT IN A DEFINED MANNER WITH THE HELP OF
    #  A KEY THE UNITS MAY BE SINGLE LETTERS THE MOST COMMON PAIRS OF LETTERS TRIPLETS OF LETTERS 
    # MIXTURES OF THE ABOVE AND SO FORTH THE RECEIVER DECIPHERS THE TEXT BY PERFORMING THE INVERSE
    #  SUBSTITUTION PROCESS TO EXTRACT THE ORIGINAL MESSAGE SUBSTITUTION CIPHERS CAN BE COMPARED 
    # WITH TRANSPOSITION CIPHERS IN A TRANSPOSITION CIPHER THE UNITS OF THE PLAINTEXT ARE REARRANGED 
    # IN A DIFFERENT AND USUALLY QUITE COMPLEX ORDER BUT THE UNITS THEMSELVES ARE LEFT UNCHANGED
    # BY CONTRAST IN A SUBSTITUTION CIPHER THE UNITS OF THE PLAINTEXT ARE RETAINED IN THE SAME 
    # SEQUENCE IN THE CIPHERTEXT BUT THE UNITS THEMSELVES ARE ALTERED." 
    # - should work very well with tuned frequency analysis.
    #  https://en.wikipedia.org/wiki/Substitution_cipher
    # This is the first 2 paragraphs converted to all caps and with punctuation removed
    ("RM XIBKGLTIZKSB Z HFYHGRGFGRLM XRKSVI RH Z NVGSLW LU VMXIBKGRMT RM DSRXS FMRGH LU KOZRMGVCG ZIV " +\
    "IVKOZXVW DRGS GSV XRKSVIGVCG RM Z WVURMVW NZMMVI DRGS GSV SVOK LU Z PVB GSV FMRGH NZB YV HRMTOV "  +\
    "OVGGVIH GSV NLHG XLNNLM KZRIH LU OVGGVIH GIRKOVGH LU OVGGVIH NRCGFIVH LU GSV ZYLEV ZMW HL ULIGS " +\
    "GSV IVXVREVI WVXRKSVIH GSV GVCG YB KVIULINRMT GSV RMEVIHV HFYHGRGFGRLM KILXVHH GL VCGIZXG GSV " +\
    "LIRTRMZO NVHHZTV HFYHGRGFGRLM XRKSVIH XZM YV XLNKZIVW DRGS GIZMHKLHRGRLM XRKSVIH RM Z " +\
    "GIZMHKLHRGRLM XRKSVI GSV FMRGH LU GSV KOZRMGVCG ZIV IVZIIZMTVW RM Z WRUUVIVMG ZMW FHFZOOB" +\
    "JFRGV XLNKOVC LIWVI YFG GSV FMRGH GSVNHVOEVH ZIV OVUG FMXSZMTVW YB XLMGIZHG RM Z HFYHGRGFGRLM " +\
    "XRKSVI GSV FMRGH LU GSV KOZRMGVCG ZIV IVGZRMVW RM GSV HZNV HVJFVMXV RM GSV XRKSVIGVCG YFG GSV " +\
    "FMRGH GSVNHVOEVH ZIV ZOGVIVW", "Expected: IN CRYPTOGRAPHY A SUBSTITUTION CIPHER... [long text]"),
]


for i, (encrypted_msg, expected) in enumerate(test_cases, 1):
    print(f"\n{'='*80}")
    print(f"TEST CASE {i}: '{encrypted_msg}'")
    print(f"({expected})")
    print('='*80)
    
    # Try brute force decryption
    best_decryption = decryptor.auto_decrypt(encrypted_msg, top_n=3)
    
    print(f"Most likely decryption: '{best_decryption}'")