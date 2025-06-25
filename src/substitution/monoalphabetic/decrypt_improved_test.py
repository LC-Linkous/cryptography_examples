#!/usr/bin/python3

##--------------------------------------------------------------------\
#   encryption_examples  
#   './encryption_examples/src/substitution/monoalphabetic/decrypt_improved_test.py'
#   Simple test cases for the improved decryption
#   No extra Claude commentary in this one.
#
#   Date: June 23, 2025
##--------------------------------------------------------------------\

from decrypt_improved import decrypt

print("=== Improved Monoalphabetic Cipher Brute Force Decryptor ===\n")

decryptor = decrypt()

test_cases = [
    ("YMWEK EMMLB", "Expected: HELLO WORLD (backwards alphabet)"),
    ("BLMME KEWMY", "Expected: HELLO WORLD (normal)"),
    ("ZBL RUXAC QWEKD JEO FUPVS EHLW ZBL MIGT YEN", "Expected: THE QUICK BROWN FOX..."),
    ("IZZIAC IZ YIKD", "Expected: ATTACK AT DAWN"),
    ("JWLRULDAT IDIMTSXS XS ZBL CLT ZE SUAALSS", "Expected: FREQUENCY ANALYSIS..."),
    ("RM XIBKGLTIZKSB Z HFYHGRGFGRLM XRKSVI RH Z NVGSLW LU VMXIBKGRMT RM DSRXS FMRGH LU KOZRMGVCG ZIV " +\
    "IVKOZXVW DRGS GSV XRKSVIGVCG RM Z WVURMVW NZMMVI DRGS GSV SVOK LU Z PVB GSV FMRGH NZB YV HRMTOV "  +\
    "OVGGVIH GSV NLHG XLNNLM KZRIH LU OVGGVIH GIRKOVGH LU OVGGVIH NRCGFIVH LU GSV ZYLEV ZMW HL ULIGS " +\
    "GSV IVXVREVI WVXRKSVIH GSV GVCG YB KVIULINRMT GSV RMEVIHV HFYHGRGFGRLM KILXVHH GL VCGIZXG GSV " +\
    "LIRTRMZO NVHHZTV HFYHGRGFGRLM XRKSVIH XZM YV XLNKZIVW DRGS GIZMHKLHRGRLM XRKSVIH RM Z " +\
    "GIZMHKLHRGRLM XRKSVI GSV FMRGH LU GSV KOZRMGVCG ZIV IVZIIZMTVW RM Z WRUUVIVMG ZMW FHFZOOB " +\
    "JFRGV XLNKOVC LIWVI YFG GSV FMRGH GSVNHVOEVH ZIV OVUG FMXSZMTVW YB XLMGIZHG RM Z HFYHGRGFGRLM " +\
    "XRKSVI GSV FMRGH LU GSV KOZRMGVCG ZIV IVGZRMVW RM GSV HZNV HVJFVMXV RM GSV XRKSVIGVCG YFG GSV " +\
    "FMRGH GSVNHVOEVH ZIV ZOGVIVW", "Expected: IN CRYPTOGRAPHY A SUBSTITUTION CIPHER... [long text]"),
]

for i, (encrypted_msg, expected) in enumerate(test_cases, 1):
    print(f"\n{'='*80}")
    print(f"TEST CASE {i}: '{encrypted_msg}'")
    print(f"({expected})")
    print('='*80)
    
    best_decryption = decryptor.auto_decrypt(encrypted_msg, top_n=3)
    print(f"Most likely decryption: '{best_decryption}'")