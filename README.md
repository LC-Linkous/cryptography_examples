# encryption_examples

This repo is a sample of some basic encryption methods, and some references for further reading. It is the public half of an interactive unit on encryption being developed for an undergraduate elective course. The full unit includes PPT slides, other VSCode examples*, and several group assignments. 

Within the `./src` directory are groups of encryption methods sorted into categories such as `substitution`, `transposition` and `grids`. The public version of this repo does not go into modern encryption methods, such as `AES`. 

Each encryption method has its own folder with the following:
* `encrypt.py` - the encryption class, standardized input.
* `decrypt.py` - the brute force decryption class, standardized input.
* `encrypt_test.py` - an LLM generated test case for encryption
* `decrypt_test.py` - an LLM generated test case for decryption

Claude AI was used to generate the test cases for the **public** version of this repo, in order to not give away any hints for the group assignments or demos. Claude AI also inserts extra commentary and examples, which is pretty fun for creating samples. `NOTE:` these test examples are very different in format from the PPT slides and demos, and shouldn't be used as a starting point for the group work. The `encrypt` and `decrypt` classes are currently 1:1 with the demos. For details on AI Usage and how it performed, see the [Notes on AI as an Instructional Tool](#notes-on-ai-as-an-instructional-tool)

*VSCode is the 'default' IDE to match the Python virtual environment tutorial that is shared between the tutorial units. Other IDEs and setups can be used if you have a preferred setup. 



## Table of Contents
* [What is Encryption?](#what-is-encryption)
* [Requirements](#requirements)
* [Implementation](#implementation)
* [Included in this Project](#included-in-this-project)
    * [Substitution Ciphers](#substitution-ciphers)
    * [Transposition Ciphers](#transposition-ciphers)
    * [Grid Ciphers](#grid-ciphers)
    * [Stream Ciphers](#stream-ciphers)
* [Some Algorithm Discussion](#some-algorithm-discussion)
    * [Substitution](#substitution)
    * [Transposition](#transposition)
    * [Grid](#grid)
    * [Stream and Hash](#stream-and-hash)
* [Notes on AI as an Instructional Tool](#notes-on-ai-as-an-instructional-tool)
    * [Tool Disclosure ](#tool-disclosure)
    * [Goal for Using AI](#goal-for-using-ai)
    * [Incorportaion and Testing](#incorportaion-and-testing)
    * [What Worked](#what-worked)
    * [What Did Not Work](#what-did-not-work)
* [References](#references)



## What is Encryption?

<p align="center">
        <img src="media/fig_encryption.png" alt="A message encrypted using a public key and decrypted using a private key" height="200">
</p>
   <p align="center">A message encrypted using a public key and decrypted using a private key </p>


Encryption is a method of making transmitted information unreadable to anyone who is not the intended sender or recipient(s). These transmissions can be text, images, raw data, or any kind of information that can be digitized and sent between at least two points. 

Algorithms for obfuscating text have been around for thousands of years. The 'Ceasar Cipher', where a message is encrypted with a shifted dictionary, is one of the most well-known early examples of a substitution cipher. Physical methods, such as using a scytale wrapped with pieces of parchment or leather to encode and decode messages in a transposition cipher have also existed for at least as long as substitution ciphers. There also exists entire secret languages that have been used in both spoken and written forms to communicate. (It turns out people have always been clever about sending secret messages!)

Why all the effort? When using complex algorithms, encryption ensures that even if the data is intercepted, it remains secure. This makes it essential for maintaining privacy and security in communications, including across the internet in the modern day. 

In the figure above, `Hello World!` is encrypted with a public key, and then sent as `EBIIL TLOIA!`. The intended receiver, who has the private key, is able to decrypt the message into the original `Hello World!`. 

This image, while simple, is a good introduction for several complex topics:

* `Public key cryptography`, also called `asymmetric cryptography`, uses a pair of keys in order to encode and decode messages. This is what is depicted in the image above. When the cryptographic algorithm is created, two keys are generated. One of these keys is the `public key` while the other is the `private key`.  The public key is known by anyone and everyone, and can be used to `verify` the message sender (the owner of the public key). The private key is known **only** by the intended message recipients, and is used to decode the message. There are several methods of combining public and private key usage in order to securely encrypt and decrypt messages. See the [References](#references) for further reading.

* With the existence of `asymmetric cryptography`, it makes sense that there is also `symmetric cryptography`. Symmetric key algorithms are algorithms that use the same key for encryption and decryption. This is the oldest and the most straightforward type of encryption. The keys can be identical, or they may have a simple reversal in order to 'undo' the encryption. This key should be thought of as a `private key`, and should only be shared between the sender and intended recipients. Having the private, shared, key is considered validation for this method. This method is less secure, but noticeably faster for encryption and transmission, which makes it appealing. 

* There also exists various hybrid methods (`hybrid cryptosystems`), which combine the benefits of both public key cryptography and symmetric cryptography. These are beyond this introduction, but have some reading in the [References](#references) section.

* `Hashing`, or hash functions, is another topic that may come up, and is a form of encryption that is intended to go in `one direction`, unlike symmetric and asymmetric methods, which are `bidirectional`. Hashing is intended for verification, not decryption. For example, passwords submitted on a banking app may be stored in a database as a generated hash value rather than storing a password directly. When a user logs in to the app, the entered password is converted to a hash and then compared to the hash value in the database. The raw text of the password is not sent. This method is outside the scope of this introduction, but may appear in some demos.


The `Hello World!` text in the figure in this section was created using the included Ceasar Cipher, making the text actually from a symmetric encryption method as the `private key` is a simple reversal of the `public key`. 


## Requirements

This repository was built and tested on Python 3.12. While effort was put into keeping the tools used in the example as generic as possible, at least Python 3.6 is needed in order to run some of the random and pseudo-random number generation functions properly.

```python
pandas
numpy
```

Optionally, requirements can be installed manually with:

```python
pip install pandas, numpy

```
This is an example for if you've had a difficult time with the requirements.txt file. Sometimes libraries are packaged together.

## Implementation

Each encryption method has its own folder with the following:
* `encrypt.py` - the encryption class, standardized input.
* `decrypt.py` - the brute force decryption class, standardized input.
* `encrypt_test.py` - an LLM generated test case for encryption
* `decrypt_test.py` - an LLM generated test case for decryption

`encrypt.py` and `decrypt.py` are stand alone and do not need the other to work. The test files use either the encrypt or decrypt classes to demonstrate how encryption and brute force encryption are used. The brute force method shown in this repo are not the only way the decrypt these, but they made good examples for the process. 

In some repositories there may be a `decrypt_improved.py` and matching `decrypt_improved_test.py`, these are more detailed in their brute force attempts, but may only be more accurate or `improved` under specific conditions. They are considered experimental and for educational purposes outside of the main demonstration. 

Regarding non-English dictionaries, there are some hooks for that integration, but it is not fully implemented into these samples to keep them simple. A directory of `default_dictionaries` has been included for generating different ASCII and Unicode dictionaries, but this is exploratory. They're also AI generated, which makes them fun to play with, but not particularly useful at this time. 



## Included in this Repository

Discussion of ciphers and history are included in the non-public half of this material, this repository is focused on the demo code.

### Substitution Ciphers

In a substitution cipher, each letter (or symbol) in the plaintext is replaced by a corresponding letter (or symbol) in the ciphertext. The simplest of these are vulnerable to decryption even without having a private key due to frequency analysis. Some methods exist to make frequency analysis less effective.

1. Ceasar Cipher
    * This cipher is attributed to Julius Ceasar, and involves and alphabetical shift. The cipher is created by taking the plaintext and shifting it by a certain number of positions down or up the alphabet. It is one of the most common 'starting' ciphers used to introduce the topic of cryptography.
2. Bacon Cipher
    * Created by Francis Bacon in 1605, this is a type of steganography rather than just a cipher. Using this method, letters are encoded rather than the message. This method works like binary representation, where two characters (typically 'A' and 'B') are used in a series of 5 to represent a numerical value of a letter. 
3. Monoalphabetic Cipher
    * This cipher creates a new dictionary with the same 1:1 relation as a Caesar Cipher, but the letters in the cipher dictionary can be randomly matched to their plaintext equivalent rather than determined by shifting.
    * This is the most difficult of the substitution ciphers in this section to brute force, and requires some tuning. HOWEVER, even when it does not preform perfectly, it often results in a starting point for further analysis. For example, a high-scoring but incorrect result is still partialy readable.


### Transposition Ciphers

A transposition cipher uses the message itself as a form of obfuscation. Rather than changing the letters (substituting), the letters in the message are rearranged to make the message unreadable. 

1. Rail Fence
    * This cipher is named for its distinctive 'zig zag' pattern where the plaintext is written up and down column'rails' and then read across the rows to create the cipher text. This can be brute forced by reconstructing the zigzag pattern.
2. Block
    * A block cipher ia s symmetric algorithm that encrpyts data in 'blocks' rather than one at a time (as in a stream cipher). This algorithm is a foundational model used in the DES algorithm.
    * The 'block' cipher in this example is a Feistel cipher (also known as Luby–Rackoff block cipher). It was named after Horst Feistel, who was a physist and cryptographer working at IBM.


### Grid Ciphers

The grid ciphers in this section have some relation to the substitution and transpostion ciphers in the previous sections, but are notable for their distinctive grid pattern used in the encoding.


1. Polybius
    * A polibus cipher uses a 5x5 grid in order to encode letters into numerical coordinates of a grid. This is a type of `substitution` cipher.
    * Attributed to the Green historian Polybius.

2. ADFGVX
    * This is a WW1 cipher used to send encrypted messages over radiotelegraphy/wireless telemetry. It is a revised version of the earlier ADFGV cipher and uses a modified Polybius square (6x6 compared to the 5x5). 
    * This is a `transposition` cipher, but is in this section due to the grid used in the algorithm. This grid form made it possible to implement manually. 



### Stream Ciphers


1. RC4 (Rivest Cipher 4)
    * RC4 is a once-popular stream cipher designed in 1987. It has since fallen into disuse due to discovered vulnerabilities. Attacks against this cipher include the 2001 [Fluhrer-Mantin-Shamir attack](https://en.wikipedia.org/wiki/Fluhrer,_Mantin_and_Shamir_attack) and attacks against biases in the keystream.

2. ChaCha20 
    * ChaCha20 generates a pseudo-random keystream which is then XOR'ed with the plaintext to encrypt it. This method requires a key and a nonce. This cipher originated in 2008 as a family of ciphers.
    * Key: a secret value, typically 32 byte/256 bits, used to initialize a cipher's state
    * Nonce: an 8-byte, 12-byte, or 24-byte number used only **once** with any given key. ChaCha20 typically uses 12 bytes/96 bits.

`NOTE about the included stream ciphers:`
* These ciphers are not 'solved' or 'decrypted' in this repo. Brute force decryption is non-trivial (read: impossible in the context of the presented cipher sample) and included with an analysis of what these ciphers are and how they are used. These are for comparison purposes.




## Some Algorithm Discussion

This section discusses the general operation of the algorithms in terms of the input, output, and some tuning. In-depth discussion is reserved for the PPTs and group assignments.


### Substitution


1. **Ceasar Cipher**

This is one of the easier algorithms to brute force given the limited solution space. The alphabet can only shift left or right, not scramble. A brute force decryption for a Ceasar Cipher involves trying every possible combination and then scoring based on English (in this case) letter frequency. 

Encryption:
```python

=== Encryption Dictionary ===
Original:  ABCDEFGHIJKLMNOPQRSTUVWXYZ
Encrypted: XYZABCDEFGHIJKLMNOPQRSTUVW

=== Encryption Examples ===
'ABC' -> 'XYZ'
'HELLO' -> 'EBIIL'
'WORLD' -> 'TLOIA'
'HELLO WORLD!' -> 'EBIIL TLOIA!'
'ABC123' -> 'XYZ123'
'ZEBRA' -> 'WBYOX'

```


Decryption:
```python

============================================================
TEST CASE 1: 'KHOOR ZRUOG'
============================================================
Trying offsets 0 to 51...
============================================================

Top 3 most likely decryptions:
============================================================
1. Offset 16 (Score: -800.8): aXeeh phkeW
2. Offset 42 (Score: -800.8): AxEEH PHKEw
3. Offset 20 (Score: -878.3): ebiil tloia

Most likely decryption: 'aXeeh phkeW'

============================================================
TEST CASE 2: 'WKH TXLFN EURZQ IRA MXPSV RYHU WKH ODCB GRJ'
============================================================
Trying offsets 0 to 51...
============================================================

Top 3 most likely decryptions:
============================================================
1. Offset 23 (Score: -171.8): the quick brown foX jumps over the laZY dog
2. Offset 49 (Score: -171.8): THE QUICK BROWN FOx JUMPS OVER THE LAzy DOG
3. Offset 13 (Score: -291.8): jXU gkYSa Rhemd VeN Zkcfi elUh jXU bQPO TeW

Most likely decryption: 'the quick brown foX jumps over the laZY dog'

============================================================
TEST CASE 3: 'JBHF GUVF VF N GRKF ZRFFNTR'
============================================================
Trying offsets 0 to 51...
============================================================

Top 3 most likely decryptions:
============================================================
1. Offset 13 (Score: -495.1): WOUS ThiS iS a TeXS meSSage
2. Offset 39 (Score: -495.1): wous tHIs Is A tExs MEssAGE
3. Offset  9 (Score: -596.8): SKQO PdeO eO W PaTO iaOOWca

Most likely decryption: 'WOUS ThiS iS a TeXS meSSage'

```



2. **Bacon Cipher**

The Bacon Cipher is another relatively straightforward cipher to brute force. It has a limited dictionary and can still be broken with frequency analysis. Each single character is replaced with a binary representation (with ‘1’ and ‘0’ replaced with any arbitrary 2 symbols), and the text is not scrambled. 

Encryption:
```python
=== Encryption Dictionary ===
Baconian cipher mapping (using 'A' and 'B'):
Variant: 26-letter (all separate)
  A -> AAAAA
  B -> AAAAB
  C -> AAABA
  D -> AAABB
  E -> AABAA
  F -> AABAB
  G -> AABBA
  H -> AABBB
  I -> ABAAA
  J -> ABAAB

=== Encryption Examples ===
'ABC' -> 'AAAAAAAAABAAABA'
'HELLO' -> 'AABBBAABAAABABBABABBABBBA'
'WORLD' -> 'BABBAABBBABAAABABABBAAABB'
'HELLO WORLD' -> 'AABBBAABAAABABBABABBABBBA BABBAABBBABAAABABABBAAABB'
'ABC123' -> 'AAAAAAAAABAAABA123'
'ZEBRA' -> 'BBAABAABAAAAAABBAAABAAAAA'


=== Different Symbol Sets ===
Symbols '0'/'1': 'HELLO' -> '0011100100010110101101110'
Symbols '.'/'-': 'HELLO' -> '..---..-...-.--.-.--.---.'
Symbols '*'/'#': 'HELLO' -> '**###**#***#*##*#*##*###*'
Symbols 'X'/'O': 'HELLO' -> 'XXOOOXXOXXXOXOOXOXOOXOOOX'

```


Decryption:
```python
================================================================================
TEST CASE 1: 'AABBBAABAAABABBABABBABBBA'
(Expected: HELLO)
================================================================================

Top 3 most likely decryptions:
================================================================================
1. Symbols: 'A'/'B' (26-letter) - Score: -1600.8
   Result: HELLO

2. Symbols: 'B'/'A' (24-letter) - Score: -1728.7
   Result: ASZKKBBBA

3. Symbols: 'B'/'A' (26-letter) - Score: -1815.1
   Result: YAXJJBBBA

Most likely decryption: 'HELLO'

================================================================================
TEST CASE 2: '100100010000010100010010010011'
(Expected: SECRET)
================================================================================

Top 3 most likely decryptions:
================================================================================
1. Symbols: '0'/'1' (26-letter) - Score: -813.2
   Result: SECRET

2. Symbols: '0'/'1' (24-letter) - Score: -891.7
   Result: TECSEU

3. Symbols: '1'/'0' (26-letter) - Score: -8343.9
   Result: 10010001A10100010010010011

Most likely decryption: 'SECRET'

================================================================================
TEST CASE 3: '....-........-..---..--.-'
(Expected: BACON)
================================================================================

Top 3 most likely decryptions:
================================================================================
1. Symbols: '.'/'-' (26-letter) - Score: -1035.9
   Result: BACON

2. Symbols: '.'/'-' (24-letter) - Score: -1186.6
   Result: BACPO

3. Symbols: '-'/'.' (26-letter) - Score: -2957.8
   Result: ...X....WG-.-

Most likely decryption: 'BACON'

================================================================================
TEST CASE 4: 'BAABBAABAABAABABAABB'
(Expected: TEST)
================================================================================

Top 3 most likely decryptions:
================================================================================
1. Symbols: 'B'/'A' (24-letter) - Score: -1621.6
   Result: NAYAXABB

2. Symbols: 'B'/'A' (26-letter) - Score: -1661.4
   Result: MAWAVABB

3. Symbols: 'A'/'B' (26-letter) - Score: -2078.8
   Result: TEST


```


3. **Monoalphabetic Cipher**

The Monoalphabetic cipher is the most difficult substitution example in this collection and requires some tuning. However, even when it does not perform perfectly, it often results in a starting point for further analysis. For example, a high-scoring but incorrect result is still partially readable. What’s happening is that the text is English-like statistically with the frequency of letter distribution, even if it is very distinctly not English. To improve the decryption, context dependent words can be added to the dictionary.


Encryption:
```python

=== Encryption Examples ===
Using random key (seed=42):
'ABC' -> 'IQA'
'HELLO' -> 'BLMME'
'WORLD' -> 'KEWMY'
'HELLO WORLD' -> 'BLMME KEWMY'
'ABC123' -> 'IQA123'
'ATTACKATDAWN' -> 'IZZIACIZYIKD'

Using custom key (alphabet backwards):
'ABC' -> 'ZYX'
'HELLO' -> 'SVOOL'
'WORLD' -> 'DLIOW'
'HELLO WORLD' -> 'SVOOL DLIOW'
'ABC123' -> 'ZYX123'
'ATTACKATDAWN' -> 'ZGGZXPZGWZDM'
```


Decryption Test Case 5, Encrypted Text:
```python
================================================================================
TEST CASE 5: '''RM XIBKGLTIZKSB Z HFYHGRGFGRLM XRKSVI RH Z NVGSLW LU VMXIBKGRMT 
RM DSRXS FMRGH LU KOZRMGVCG ZIV IVKOZXVW DRGS GSV XRKSVIGVCG RM Z WVURMVW NZMMVI 
DRGS GSV SVOK LU Z PVB GSV FMRGH NZB YV HRMTOV OVGGVIH GSV NLHG XLNNLM KZRIH 
LU OVGGVIH GIRKOVGH LU OVGGVIH NRCGFIVH LU GSV ZYLEV ZMW HL ULIGS GSV IVXVREVI
WVXRKSVIH GSV GVCG YB KVIULINRMT GSV RMEVIHV HFYHGRGFGRLM KILXVHH GL VCGIZXG 
GSV LIRTRMZO NVHHZTV HFYHGRGFGRLM XRKSVIH XZM YV XLNKZIVW DRGS GIZMHKLHRGRLM 
XRKSVIH RM Z GIZMHKLHRGRLM XRKSVI GSV FMRGH LU GSV KOZRMGVCG ZIV IVZIIZMTVW
RM Z WRUUVIVMG ZMW FHFZOOBJFRGV XLNKOVC LIWVI YFG GSV FMRGH GSVNHVOEVH ZIV 
OVUG FMXSZMTVW YB XLMGIZHG RM Z HFYHGRGFGRLM XRKSVI GSV FMRGH LU GSV KOZRMGVCG 
ZIV IVGZRMVW RM GSV HZNV HVJFVMXV RM GSV XRKSVIGVCG YFG GSV FMRGH GSVNHVOEVH ZIV 
ZOGVIVW'''
(Expected: IN CRYPTOGRAPHY A SUBSTITUTION CIPHER... [long text])
```

Iteration with 'default' dictionary. Score: 2269.6
```python
'''ON CRBUTPKRAUHB A IMWITOTMTOPN COUHER OI A GETHPD PL ENCRBUTONK ON XHOCH MNOTI 
PL USAONTEFT ARE REUSACED XOTH THE COUHERTEFT ON A DELONED GANNER XOTH THE HESU PL 
A QEB THE MNOTI GAB WE IONKSE SETTERI THE GPIT CPGGPN UAORI PL SETTERI TROUSETI PL 
SETTERI GOFTMREI PL THE AWPVE AND IP LPRTH THE RECEOVER DECOUHERI THE TEFT WB
 UERLPRGONK THE ONVERIE IMWITOTMTOPN URPCEII TP EFTRACT THE PROKONAS GEIIAKE 
 IMWITOTMTOPN COUHERI CAN WE CPGUARED XOTH TRANIUPIOTOPN COUHERI ON A TRANIUPIOTOPN 
 COUHER THE MNOTI PL THE USAONTEFT ARE REARRANKED ON A DOLLERENT AND MIMASSBJMOTE 
 CPGUSEF PRDER WMT THE MNOTI THEGIESVEI ARE SELT MNCHANKED WB CPNTRAIT ON A 
 IMWITOTMTOPN COUHER THE MNOTI PL THE USAONTEFT ARE RETAONED ON THE IAGE IEJMENCE 
 ON THE COUHERTEFT WMT THE MNOTI THEGIESVEI ARE ASTERED'''
  
Key sample: P->Q, J->J, B->B, K->U, Z->A, W->D, N->G, S->H, E->V, H->I...

```

Iteration with ['SUBSTITUTION','METHOD'] added to the dictionary. Score: 2490.9
```python
'''IN CRBSTOGRASHB A DJKDTITJTION CISHER ID A METHOP OU ENCRBSTING IN WHICH JNITD OU 
SLAINTEFT ARE RESLACEP WITH THE CISHERTEFT IN A PEUINEP MANNER WITH THE HELS OU A QEB 
THE JNITD MAB KE DINGLE LETTERD THE MODT COMMON SAIRD OU LETTERD TRISLETD OU LETTERD
MIFTJRED OU THE AKOVE ANP DO UORTH THE RECEIVER PECISHERD THE TEFT KB SERUORMING THE
INVERDE DJKDTITJTION SROCEDD TO EFTRACT THE ORIGINAL MEDDAGE DJKDTITJTION CISHERD CAN 
KE COMSAREP WITH RANDSODITION CISHERD IN A TRANDSODITION CISHER THE JNITD OU THE 
SLAINTEFT ARE REARRANGEP IN A PIUUERENT ANP JDJALLBXJITE COMSLEF ORPER KJT THE JNITD 
THEMDELVED ARE LEUT JNCHANGEP KB CONTRADT IN A DJKDTITJTION CISHER THE JNITD OU THE 
SLAINTEFT ARE RETAINEP IN THE DAME DEXJENCE IN THE CISHERTEFT KJT THE JNITD THEMDELVED 
ARE ALTEREP'''

Key sample: R->I, B->B, F->J, O->L, D->W, G->T, S->H, I->R, Z->A, H->D...

```

Iteration with ['CRYPTOGRAPHY','SUBSTITUTION','CIPHER','METHOD','ENCRYPT'] added to the dictionary. Score: 2706.2

```python
'''IN CRYPTOGRAPHY A UMKUTITMTION CIPHER IU A SETHOD OF ENCRYPTING IN WHICH MNITU OF 
PLAINTEXT ARE REPLACED WITH THE CIPHERTEXT IN A DEFINED SANNER WITH THE HELP OF A BEY 
THE MNITU SAY KE UINGLE LETTERU THE SOUT COSSON PAIRU OF LETTERU TRIPLETU OF LETTERU 
SIXTMREU OF THE AKOVE AND UO FORTH THE RECEIVER DECIPHERU THE TEXT KY PERFORSING THE 
INVERUE UMKUTITMTION PROCEUU TO EXTRACT THE ORIGINAL SEUUAGE UMKUTITMTION CIPHERU CAN
KE COSPARED WITH RANUPOUITION CIPHERU IN A TRANUPOUITION CIPHER THE MNITU OF THE
PLAINTEXT ARE REARRANGED IN A DIFFERENT AND MUMALLYJMITE COSPLEX ORDER KMT THE MNITU 
THESUELVEU ARE LEFT MNCHANGED KY CONTRAUT IN A UMKUTITMTION CIPHER THE MNITU OF THE 
PLAINTEXT ARE RETAINED IN THE UASE UEJMENCE IN THE CIPHERTEXT KMT THE MNITU 
THESUELVEU ARE ALTERED'''

Key sample: Z->A, R->I, M->N, G->T, S->H, V->E, I->R, H->U, L->O, K->P...

```


### Transposition

1. Rail Fence

The Rail Fence cipher can be brute forced by working backwards from the length of the message to the number of rails. One difficulty here is that the letter frequency is preserved due to the words being scrambled. An exhaustive search is possible, given that the maximum number of rails in a text of length N is N rails. However, pattern analysis will likely yield results quicker.


Encryption:
```python
=== 3 Rails, Direction: down, Remove Spaces: True ===
Rail Fence cipher with 3 rails:
Direction: down
Text length: 10

Rail visualization:
Rail 0: H   O   L
Rail 1:  E L W R D
Rail 2:   L   O

Rail pattern: [0, 1, 2, 1, 0, 1, 2, 1, 0, 1]

Original:  'HELLO WORLD'
Encrypted: 'HOLELWRDLO'
Decrypted: 'HELLOWORLD'
Match: True

=== 4 Rails, Direction: down, Remove Spaces: True ===
Rail Fence cipher with 4 rails:
Direction: down
Text length: 10

Rail visualization:
Rail 0: H     O
Rail 1:  E   W R
Rail 2:   L O   L
Rail 3:    L     D

Rail pattern: [0, 1, 2, 3, 2, 1, 0, 1, 2, 3]

Original:  'HELLO WORLD'
Encrypted: 'HOEWRLOLLD'
Decrypted: 'HELLOWORLD'
Match: True

```


Decryption:
```python
Detailed analysis of: 'HOLELWRDLO'
(Correct encryption of 'HELLOWORLD' with 3 rails)
=== Detailed Analysis: 2 Rails ===
Encrypted:  'HOLELWRDLO'
Decrypted:  'HWORLDELLO'
Score:      -900.0
Text length: 10
Pattern period: 2
Rail distribution: {0: 5, 1: 5}
Pattern sample: [0, 1, 0, 1, 0, 1, 0, 1, 0, 1]

Rail visualization:
Rail 0: H O L E L
Rail 1:  W R D L O

=== Detailed Analysis: 3 Rails ===
Encrypted:  'HOLELWRDLO'
Decrypted:  'HELLOWORLD'
Score:      -870.0
Text length: 10
Pattern period: 4
Rail distribution: {0: 3, 1: 5, 2: 2}
Pattern sample: [0, 1, 2, 1, 0, 1, 2, 1, 0, 1]

Rail visualization:
Rail 0: H   O   L
Rail 1:  E L W R D
Rail 2:   L   O

=== Detailed Analysis: 4 Rails ===
Encrypted:  'HOLELWRDLO'
Decrypted:  'HLWLREOLDO'
Score:      -918.0
Text length: 10
Pattern period: 6
Rail distribution: {0: 2, 1: 3, 2: 3, 3: 2}
Pattern sample: [0, 1, 2, 3, 2, 1, 0, 1, 2, 3]

Rail visualization:
Rail 0: H     O
Rail 1:  L   E L
Rail 2:   W R   D
Rail 3:    L     O

=== Detailed Analysis: 5 Rails ===
Encrypted:  'HOLELWRDLO'
Decrypted:  'HLWDOLREOL'
Score:      -913.0
Text length: 10
Pattern period: 8
Rail distribution: {0: 2, 1: 3, 2: 2, 3: 2, 4: 1}
Pattern sample: [0, 1, 2, 3, 4, 3, 2, 1, 0, 1]

Rail visualization:
Rail 0: H       O
Rail 1:  L     E L
Rail 2:   W   R
Rail 3:    D L
Rail 4:     O
```



2. Block

Classical ciphers have search space of  26! ≈ 4×10²⁶, but this type of cipher has a search space on the scale of 2¹²⁸ ≈ 3×10³⁸ (AES-128), making it impossible to attempt an exhaustive search on your average computer. Instead, more intelligent attacks must be utilized to get the key for decryption. The decryption files included for this example only provide an analysis of a sample of search results based on user settings. This algorithm is a good comparison, however, because it is the backbone of modern-day encryption.

Encryption:
```python
================================================================================
CONFIGURATION 1
================================================================================
Block Cipher Configuration:
  Block size: 8 bytes
  Number of rounds: 3
  Key: 0123456789ABCDEF
  Padding mode: PKCS7
  Output format: hex

S-box (first 16 values): ['0xe4', '0x6', '0x4f', '0xce', '0x75', '0xb9', '0xf2', '0xa7', '0x9', '0x1e', '0xb4', '0xde', '0xe6', '0xd9', '0x88', '0x44']     
P-box (bit positions): [0, 1, 3, 7, 4, 2, 5, 6]

Round keys:
  Round 1: 2344658AAFC8E906
  Round 2: 44678AA9C8EB0625
  Round 3: 658AABCCE9062740

=== Testing Messages ===
'HELLO' -> '84448CA0F2AD4F7D' -> 'HELLO' (Match: True)
'HELLO WORLD' -> '84448CA0F254C2B0F4B508E07FB449A3' -> 'HELLO WORLD' (Match: True)
'THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG' -> '1D246C09677927883482F6C1F24362D44449BE097B7910811482C6A6DBE0EBF68444D0A0ED6B95D4C749B8E07FB449A3' -> 'THE 
QUICK BROWN FOX JUMPS OVER THE LAZY DOG' (Match: True)

```


Decryption (attempt. There are no results here):
```python
=== Analysis of Unknown Ciphertext ===
Ciphertext: A1B2C3D4E5F67890A1B2C3D4E5F67890A1B2C3D4E5F67890A1B2C3D4E5F67890A1B2C3D4E5F67890A1B2C3D4E5F67890A1B2C3D4E5F67890A1B2C3D4E5F67890
=== Comprehensive Block Cipher Cryptanalysis ===
Analyzing 8 blocks of 8 bytes each

============================================================
=== Statistical Randomness Tests ===
Chi-square test (byte frequency):
  Chi-square statistic: 1922.00
  Expected for random: ~255
  Assessment: FAIL

Runs test (consecutive bytes):
  Observed runs: 63
  Expected runs: 31.5
  Deviation: 1.000
  Assessment: FAIL

Autocorrelation test (lag=1):
  Correlation coefficient: 0.2946
  Assessment: FAIL

============================================================
=== Frequency Analysis Attack ===
Analyzed 8 ciphertext blocks
Block frequency analysis:
  a1b2c3d4e5f67890: 8 times (100.000%)

Repeated blocks (ECB vulnerability): 1

Byte frequency by position:
  Position 0: 0xA1 appears 8 times (100.000%)
  Position 1: 0xB2 appears 8 times (100.000%)
  Position 2: 0xC3 appears 8 times (100.000%)
  Position 3: 0xD4 appears 8 times (100.000%)
  Position 4: 0xE5 appears 8 times (100.000%)
  Position 5: 0xF6 appears 8 times (100.000%)
  Position 6: 0x78 appears 8 times (100.000%)
  Position 7: 0x90 appears 8 times (100.000%)

============================================================
=== Exhaustive Key Search (max 1000 keys) ===
Key space: 2^16 = 65,536 total keys
Testing only 1,000 keys for demonstration...
Found 0 candidate keys
```



### Grid

1. Polybius

The Polybius cipher is possible to brute force due to its size (5x5 or 6x6), making an exhaustive search possible. While the Polybius Square can be randomized, there are still a limited number of cells. Frequency analysis can also be used to decode this cypher without reconstructing the original grid. This makes the decryption methods similar to the Monoalphabetic cipher shown earlier.


Encryption:
```python
================================================================================
CONFIGURATION 1
================================================================================
Polybius Square (5x5):
Combined letters: IJ
Number base: 1 (1-based)
    1  2  3  4  5
 1  F  U  Y  R  H
 2  Q  Z  X  G  V
 3  P  S  K  A  L
 4  N  D  T  C  B
 5  W  O  E  M

Coordinate examples:
  A → 34
  E → 53
  M → 54
  Z → 22

Grid Statistics:
  grid_size: 5x5
  total_positions: 25
  filled_positions: 24
  keyword_used: False
  combine_letters: IJ
  number_base: 1
  separator: ' '

=== Testing Messages ===
'HELLO' -> '15 53 35 35 52' -> 'HELLO' (Match: True)
'HELLO WORLD' -> '15 53 35 35 52   51 52 14 35 42' -> 'HELLOWORLD' (Match: False)
  Note: J→I substitution expected with IJ combination
'ATTACK AT DAWN' -> '34 43 43 34 44 33   34 43   42 34 51 41' -> 'ATTACKATDAWN' (Match: False)
  Note: J→I substitution expected with IJ combination

================================================================================
CONFIGURATION 3
================================================================================
Polybius Square (5x5):
Combined letters: IJ
Number base: 0 (0-based)
    0  1  2  3  4
 0  B  F  C  R  A
 1  S  E  T  P  O
 2  K  U  X  W  L
 3  N  Q  H  Z  M
 4  D  V  Y  G

Coordinate examples:
  A → 04
  E → 11
  M → 34
  Z → 33

Grid Statistics:
  grid_size: 5x5
  total_positions: 25
  filled_positions: 24
  keyword_used: False
  combine_letters: IJ
  number_base: 0
  separator: '-'

=== Testing Messages ===
'HELLO' -> '32-11-24-24-14' -> 'HELLO' (Match: True)
'HELLO WORLD' -> '32-11-24-24-14- -23-14-03-24-40' -> 'HELLO WORLD' (Match: True)
'ATTACK AT DAWN' -> '04-12-12-04-02-20- -04-12- -40-04-23-30' -> 'ATTACK AT DAWN' (Match: True)


```

Decryption:
```python
=== CREATING PROPER TEST CASES ===
Standard grid coordinate mapping:
  H → 23
  E → 15
  L → 25
  O → 33
  W → 51
  R → 41
  D → 14

'HELLO WORLD' encrypts to: 23 15 25 25 33 51 33 41 25 14

SECRET grid coordinate mapping:
  S → 11
  E → 12
  C → 13
  R → 14
  T → 15

'SECRET' encrypts to: 11 12 13 14 12 15

============================================================
TEST: Standard Grid - HELLO WORLD
============================================================
=== Ciphertext Analysis ===
Text: 23 15 25 25 33 51 33 41 25 14
Length: 29
Possible separators found: [' ']
Coordinate pairs found: 10
Sample pairs: ['23', '15', '25', '25', '33', '51', '33', '41', '25', '14']
Row coordinates: 1 to 5
Col coordinates: 1 to 5
Likely 1-based numbering
Suggested grid size: 5x5
Suggested number base: 1

Correct Grid Configuration:
Polybius Square (5x5):
Standard alphabetical arrangement
Combined letters: IJ
Number base: 1 (1-based)
    1  2  3  4  5
 1  A  B  C  D  E
 2  F  G  H  K  L
 3  M  N  O  P  Q
 4  R  S  T  U  V
 5  W  X  Y  Z

Coordinate examples:
  11 → A
  15 → E
  31 → M
  54 → Z

Known decryption: 'HELLOWORLD'
Expected: 'HELLOWORLD'
Match: True

```


2. ADFGVX

The use of a 2-step substitution and transposition (or the reverse, depending on if you're encrypting or decrypting) makes this trickier to decode than the Polybius Cipher even though they may take up the same physical size for the grid. However, this algorithm is still possible to brute force through an exhaustive search or frequency analysis. 


Encryption:
```python
================================================================================
CONFIGURATION 1
================================================================================
ADFGVX Cipher Configuration:
Random Grid (seed: 42)
Transposition Keyword: 'SECRET'
Transposition Order: [4, 2, 1, 3, 5]

Substitution Grid (6x6):
   A  D  F  G  V  X
A   J  M  F  1  6  T
D   4  Z  W  0  5  K
F   L  2  I  U  Q  9
G   G  Y  A  8  N  S
V   C  7  3  V  D  X
X   E  O  P  R  B  H

Substitution Examples:
  A → GF
  E → XA
  M → AD
  Z → DD
  5 → DV
  9 → FX

Cipher Statistics:
  cipher_type: ADFGVX
  grid_size: 6x6
  total_characters: 36
  grid_keyword_used: False
  grid_keyword: None
  transposition_keyword: SECRET
  transposition_length: 5
  transposition_order: [4, 2, 1, 3, 5]
  random_seed: 42
  separator: ''

=== Testing Messages ===
'HELLO' -> 'XAXFAXXAFD'
'HELLO WORLD' -> 'XAXAXFFFAXDVXADGFDXV'
'ATTACK AT DAWN' -> 'AFGVGFGXVFXVFGVGXDXDAAAFX'

```




Decryption:
```python
=== CREATING PROPER TEST CASES ===
Test cipher configuration:        
ADFGVX Cipher Configuration:      
Random Grid (seed: 42)
Transposition Keyword: 'KEY'      
Transposition Order: [2, 1, 3]    

Substitution Grid (6x6):
   A  D  F  G  V  X
A   J  M  F  1  6  T 
D   4  Z  W  0  5  K 
F   L  2  I  U  Q  9 
G   G  Y  A  8  N  S 
V   C  7  3  V  D  X
X   E  O  P  R  B  H

Coordinate examples:
  GF → A
  XA → E
  AD → M
  DD → Z
  DV → 5
  FX → 9

=== MANUAL ENCRYPTION TRACE (for testing) ===
Let's trace how 'HELLO' would be encrypted with this configuration:
Grid lookup (manual):
Character → Coordinate mapping:
  H → XX
  E → XA
  L → FA
  L → FA
  O → XD
After substitution: 'XXXAFAFAXD'
Transposition keyword: 'KEY'
Alphabetical order: [2, 0, 1]
Padded substituted text: 'XXXAFAFAXDXX'
Row 1: X X X
Row 2: A F A
Row 3: F A X
Row 4: D X X
Column E: 'XFAX'
Column K: 'XAFD'
Column Y: 'XAXX'
Simulated encrypted result: 'XFAX XAFD XAXX'

=== TESTING DECRYPTION ===
Decrypted result: 'HELLO'
Original message: 'HELLO'
Match: True

=== STEP-BY-STEP DEMONSTRATION ===
=== ADFGVX CIPHER DECRYPTION DEMONSTRATION ===
Encrypted text: 'XFAX XAFD XAXX'
ADFGVX Cipher Configuration:
Random Grid (seed: 42)
Transposition Keyword: 'KEY'
Transposition Order: [2, 1, 3]

Substitution Grid (6x6):
   A  D  F  G  V  X
A   J  M  F  1  6  T
D   4  Z  W  0  5  K
F   L  2  I  U  Q  9
G   G  Y  A  8  N  S
V   C  7  3  V  D  X
X   E  O  P  R  B  H

Coordinate examples:
  GF → A
  XA → E
  AD → M
  DD → Z
  DV → 5
  FX → 9

=== STEP 1: REVERSE TRANSPOSITION ===
After reversing transposition: 'XXXAFAFAXD'

=== STEP 2: REVERSE SUBSTITUTION ===
Coordinate pairs to decode:
  XX → H
  XA → E
  FA → L
  FA → L
  XD → O
Final decrypted text: 'HELLO'
Demo result: 'HELLO'


```



### Stream and Hash


1. RC4 

TEXT HERE

Encryption:
```python

RC4 State Information:
  Key: 'SECRET'

=== Testing Messages ===
'HELLO' → D42B203340
'RC4' → CE2D58
'HELLO WORLD' → D42B203340007487B02AF8


RC4 State Information:
  Key: 'ThisIsALongerSecretKey123'

=== Testing Messages ===
'HELLO' → 3099B29409
'RC4' → 2A9FCA
'HELLO WORLD' → 3099B2940970426389CECB

```


Decryption:
```python


```


2. ChaCha20

TEXT HERE

Encryption:
```python
ChaCha20 State Information:
  Key: 'SECRET' (6 chars)
  Nonce: 'nonce123' (8 chars)
  Counter: 0
  Output format: HEX

=== Testing Messages ===
'HELLO' → 050124EBD0
'ChaCha20 is fast!' → 0E2C09E4F71426663B32E3B6306A728BD8
'Modern stream cipher' → 002B0CC2ED1B34256F29F5F73B2B629689E4A733    

```

Decryption:
```python


```



## Notes on AI as an Instructional Tool

### Tool Disclosure 

A paid version of Claude AI (https://claude.ai) was used in this project as detailed below. To keep things consistent, no other AI tools were used. 


### Goal for Using AI

1. Evaluate the viability of using an AI tool to generate examples & toy problems for demonstrations on this topic.
    * Is it efficient?
    * Is it accurate?
    * Is it readable and easy to follow?

2. Given a template and limited instruction, can an AI tool be used to 
    * Does this make this topic more accessable to students?
    * Does this provide more experimental opportunity?
    * Could students use this tool to reasonably test their own ciphers with a similar format?
    * At what algorithm ocmplexity (or type of algorithm), does the AI tool usage conflict with goal 1?


### Incorportaion and Testing

* Claude AI was provided the Ceasar Cipher encryption and brute force decryption algoritms as a template/starting point. I wrote the initial version of those algorithms and then asked Claude to improve on the structure and readability. It took several iterations to get a balance between extra features and the format that I wanted for modularity purposes (see the Pandas dataframe for importing algorithm specific variables for the encrypt class). The substitution ciphers were writen prior to this exercise, though not in the current class structure. 

* The bulk of the `encrypt` and `decrypt` classes were written first locally, and then the AI tool was used to:
 * 1. Create some consistency between naming within a class, and across the different algorithms
 * 2. Add (and spell check) comments, though this took manual editing to add some information relating to the unit material this repo was developed for
 * 3. Make minor edits when the encryption and decription algorithms were slow or did not apepar to output correctly.
    * The algorithms were overall correct, though the stream ciphers had some minor errors.
    * Claude AI's preview/debug of algorithm steps where the visual representation is printed out were a vast improvement on mine.


* Claude AI was used to generate the `encrypt_test.py` and `decrypt_test.py` classes. I made very few edits to those (primarily to correct some facutual errors or non-existant function calls)

* For comparison purposes, Claude AI was told to make a version of `transposition/block/decrypt.py` and corresponding test function where it could make changes, additions, and commentary to improve the accuracy of the brute force decryption. 
    * This had an increased PASS rate of test cases, but upon closer inspection this is because specific words unique to the testcases were inserted into the ditionary by Claude AI. 
    * On the given test cases there was no noticable improvement on the brute force algorithm in general.

* Overall, an AI tool was useful, but it had a tendency to insert excessive commentary, remove key comments in the code about modification, and make edits to the code to falsely increase the pass rate of test cases. These algorithms are also very well known, so there were no issues with training data behind the LLM.


### What Worked

1. From a programming and editing perspective:
    * The function renaming to be a common structure was appreciated. This made the process of checking that all functions were consistently named very fast. The code also looks cleaner
    * Asking Claude AI to comment, or to increase the number of comments in the code I provided it was ultimately mixed. It added a lot of comments that were distrcting from the actual implementation. This was rolled back.
        * Comments provided on the `encrypt_test.py` functions as these are relatively self contained and don't need to be included in every use of the algorithms, these were largely left as-is.


2. From a content perspective:
    * Generating the test cases for encryption and decryotion was overall a positive experience. The test cases are unique enough from my demonstrations that they can be released publically and still demonstrate the encryption and decryption process. They also included display and analysis that I was not expecting.
    * The commentary, when in the test files, was overall interesting and did explain individual algorithm steps fairly well
    * Some of the code generation just for algorithm explanation and preview. This was useful for demonstration in this use case.


3. Debug and preview
    * Claude AI's printout of algorithm progress, and the visualization of the algorithms were better than mine, no competition. This was especially true with the `Rail Fence` and `grid` alogrithms that required some ASCII art.


### What Did Not Work

1. Surprise code & comment changes
    *  Claude AI had a tendency to change code even when instructed not to. Some of this was for readability, or to increase modularity. Other times it was additional to the initial algorithm. 
    * In many cases, Claude AI removed my comments completely or replaced them with function descriptions. While this is not aninstant negative thing, it did notably remove algorithm discussion and some troubleshooting tips.
    * Some additions were overly specfic to the test cases that Claude AI generated for the test scripts. While this increased the pass rate of teh test cases, it did not actually improve the algorithm.


2. AI edits to falsely pass test cases
    * Somewhat expected, Claude would make edits to the dictionaries in the decryption process (and sometimes the code structure itself) in order for the test cases to pass. 


3. AI Generated Commentary
    * (disclaimer: no attempt was made to instruct otherwise)
    * Claude inserted a lot of commentary into the test cases for encryption and decryption, some of which wad off topic.
    * When fed multiple algorithms in the same chat, it would begin to compare them unprompted. This was not a bad thing, but discussion was intended to be reserved for outside the encryption and decryption process. When Claude was allowed to make modifications (See `transposition/block/decrypt_improved_test.py`), it inserted a lot of commentary and tended to make modifications





## References

These are general references. As related tutorials and some demos become public, information will be added.

**Types of Encryption:** 
1. Wikipedia, “Public-key cryptography,” Wikipedia, Jul. 19, 2019. https://en.wikipedia.org/wiki/Public-key_cryptography
    * Has links to other pages of interest, and some history. Current (6/2025) images are also good.

2. pago, “‘Symmetric, Asymmetric, and Hashing: Exploring the Different Types of Cryptography,’” Medium, Mar. 21, 2023. https://pagorun.medium.com/symmetric-asymmetric-and-hashing-exploring-the-different-types-of-cryptography-c4b5b9590b44

3. ClickSSL, “What is Encryption? – A Detailed Guide,” ClickSSL, Feb. 11, 2024. https://www.clickssl.net/blog/what-is-encryption
    * Explanation of different types of encryption, some examples for both.

4. R. Awati, “What is a Public Key and How Does it Work?,” SearchSecurity. https://www.techtarget.com/searchsecurity/definition/public-key

5. Wikipedia, “Public-key cryptography,” Wikipedia, Jul. 19, 2019. https://en.wikipedia.org/wiki/Public-key_cryptography

6. GeeksforGeeks, “Difference between Private key and Public key,” GeeksforGeeks, May 13, 2019. https://www.geeksforgeeks.org/computer-networks/difference-between-private-key-and-public-key/

7. GeeksforGeeks, “What is Hashing?,” GeeksforGeeks, Jun. 12, 2014. https://www.geeksforgeeks.org/dsa/what-is-hashing/ (accessed Jun. 25, 2025).
    * This is an explanation of Hashing in terms of the process and as data storage. The process of generating a hash is covered, but not in terms of usage with passwords. 

8. C. Crane, “What Is a Hash Function in Cryptography? A Beginner’s Guide,” Hashed Out by The SSL StoreTM, Jan. 25, 2021. https://www.thesslstore.com/blog/what-is-a-hash-function-in-cryptography-a-beginners-guide/


**History, Cryptography, and Ciphers**

9. J. Schneider, “The History of Cryptography | IBM,” Ibm.com, Jul. 17, 2024. https://www.ibm.com/think/topics/cryptography-history
    * A sample of cryptography through history, includes some of IBM's ideas on quantum computing

10. H. Sidhpurwala, “A Brief History of Cryptography,” www.redhat.com, Jan. 12, 2023. https://www.redhat.com/en/blog/brief-history-cryptography

11. Wikipedia, “History of cryptography,” Wikipedia, Apr. 07, 2019. https://en.wikipedia.org/wiki/History_of_cryptography
    * As always, not a primary source itself, but inlusdes a collection of interesting references and links to many, many interesting related topics

12. T. M. P. Reader, “The Clue to the Labyrinth: Francis Bacon and the Decryption of Nature,” The MIT Press Reader, Feb. 27, 2023. https://thereader.mitpress.mit.edu/the-clue-to-the-labyrinth-francis-bacon-and-the-decryption-of-nature/

13. GeeksforGeeks, “Baconian Cipher,” GeeksforGeeks, Jun. 27, 2017. https://www.geeksforgeeks.org/python/baconian-cipher/
    * Includes code example

14. “Baconian Cipher - Francis Bacon Code AABAA - Online Decoder, Solver,” www.dcode.fr. https://www.dcode.fr/bacon-cipher
    * Life demo encocde and decode from a website that has a large selection of ciphers, games, and cryptography facts
    
15. GeeksForGeeks, “Caesar Cipher in Cryptography,” GeeksforGeeks, Jun. 02, 2016. https://www.geeksforgeeks.org/caesar-cipher-in-cryptography/
    * Good explanation, demonstration, and code example

16. “Mono-Alphabetic Substitution Cipher,” 101 Computing, Nov. 09, 2019. https://www.101computing.net/mono-alphabetic-substitution-cipher/
    * Life demo website for testing monoalphabetic ciphers

17. “Monoalphabetic Substitution Cipher - Online Cryptogram Decoder, Solver,” www.dcode.fr. https://www.dcode.fr/monoalphabetic-substitution
    * Life demo encocde and decode from a website that has a large selection of ciphers, games, and cryptography facts
    
18. GeeksforGeeks, “What is Monoalphabetic Cipher?,” GeeksforGeeks, May 07, 2024. https://www.geeksforgeeks.org/computer-networks/what-is-monoalphabetic-cipher/
    * Also includes affine cipher definition

19. GeeksforGeeks, “Difference between Monoalphabetic Cipher and Polyalphabetic Cipher,” GeeksforGeeks, Jun. 08, 2020. https://www.geeksforgeeks.org/computer-networks/difference-between-monoalphabetic-cipher-and-polyalphabetic-cipher/

20. “Rail Fence Cipher,” Crypto Corner, 2017. https://crypto.interactive-maths.com/rail-fence-cipher.html
    * Interactive encode and decode

21. “Rail Fence,” rumkin.com. https://rumkin.com/tools/cipher/rail-fence/
    * Interactive encode and decode

22. “Rail Fence Cipher - Encryption and Decryption,” GeeksforGeeks, Jan. 20, 2017. https://www.geeksforgeeks.org/rail-fence-cipher-encryption-decryption/
    * Good explanation, demonstration, and code example

23. “Polybius square cipher – Encrypt and decrypt online,” cryptii. https://cryptii.com/pipes/polybius-square
    * Online encryption and decryption

24. “Polybius Square Cipher - GeeksforGeeks,” GeeksforGeeks, Feb. 18, 2018. https://www.geeksforgeeks.org/polybius-square-cipher/
    * Good explanation, demonstration, and code example

25. Wikipedia, “Feistel cipher,” Wikipedia, Nov. 25, 2019. https://en.wikipedia.org/wiki/Feistel_cipher
    * The block cipher used in this repo

26. GeeksforGeeks, “Feistel Cipher,” GeeksforGeeks, Mar. 02, 2020. https://www.geeksforgeeks.org/python/feistel-cipher/ (accessed Jun. 25, 2025).

27. “ADFGVX cipher,” Wikipedia, Feb. 24, 2022. https://en.wikipedia.org/wiki/ADFGVX_cipher

28. “ADFGVX Cipher - Decoder, Encoder, Solver, Translator,” www.dcode.fr. https://www.dcode.fr/adfgvx-cipher
    * Online encryption and decryption

29. “ADFGVX Cipher,” Crypto Corner. https://crypto.interactive-maths.com/adfgvx-cipher.html
    * Good explanation, demonstration, and code example. Links on website to other interesting ciphers

30. “Practical Cryptography,” Practicalcryptography.com, 2009. http://practicalcryptography.com/ciphers/adfgvx-cipher/

31. GeeksforGeeks, “RC4 Encryption Algorithm,” GeeksforGeeks, Mar. 23, 2018. https://www.geeksforgeeks.org/rc4-encryption-algorithm/

32. “RC4 Cipher - ArcFour - Online Decoder, Encryption,” Dcode.fr, 2025. https://www.dcode.fr/rc4-cipher

33. Wikipedia, “RC4,” Wikipedia, Dec. 31, 2019. https://en.wikipedia.org/wiki/RC4

34. “The ChaCha family of stream ciphers,” Cr.yp.to, 2024. https://cr.yp.to/chacha.html

35. Wikipedia, “Salsa20,” Wikipedia, Mar. 16, 2023. https://en.wikipedia.org/wiki/Salsa20

36. “Salsa20 — PyCryptodome 3.23.0 documentation,” Readthedocs.io, 2025. https://pycryptodome.readthedocs.io/en/latest/src/cipher/salsa20.html (accessed Jun. 25, 2025).
    * Example implementation for generating and using Salsa20 from the Cipher library in Python

37. GeeksforGeeks, “Stream Ciphers,” GeeksforGeeks, Oct. 09, 2020. https://www.geeksforgeeks.org/computer-networks/stream-ciphers/
