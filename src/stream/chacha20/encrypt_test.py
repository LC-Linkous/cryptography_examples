#! /usr/bin/python3

##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/stream/chacha20/encrypt_test.py'
#   Some (mostly) AI generated test cases, for fun. 
#   Claude also added some additional commentary, which is neat. 
#
#   Last update: June 25, 2025
##--------------------------------------------------------------------\

import pandas as pd

from encrypt import encrypt


print("=== ChaCha20 Stream Cipher Example ===")

# Test different ChaCha20 configurations
configurations = [
    # Basic ChaCha20
    {
        'name': 'ChaCha20 Basic',
        'KEY': ['SECRET'],
        'NONCE': ['nonce123'],
        'COUNTER': [0],
        'OUTPUT_FORMAT': ['HEX'],
        'SHOW_STEPS': [False]
    },
    
    # ChaCha20 with detailed steps
    {
        'name': 'ChaCha20 Detailed',
        'KEY': ['DEMO'],
        'NONCE': ['test'],
        'COUNTER': [0],
        'OUTPUT_FORMAT': ['HEX'],
        'SHOW_STEPS': [True]
    },
    
    # ChaCha20 with different counter
    {
        'name': 'ChaCha20 Counter=5',
        'KEY': ['TESTKEY'],
        'NONCE': ['mynonce'],
        'COUNTER': [5],
        'OUTPUT_FORMAT': ['BASE64'],
        'SHOW_STEPS': [False]
    }
]

test_messages = [
    "HELLO",
    "HELLO WORLD!",
    "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG"
]

for config in configurations:
    print(f"\n{'='*70}")
    print(f"CONFIGURATION: {config['name']}")
    print('='*70)
    
    # Create cipher instance
    options = pd.DataFrame(config)
    cipher = encrypt(None, options)
    
    # Show cipher state
    cipher.show_chacha20_state()
    
    # Show statistics
    stats = cipher.get_cipher_stats()
    print(f"\nChaCha20 Statistics:")
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    # Test encryption
    print(f"\n=== Testing Messages ===")
    
    # For detailed steps, only test short messages
    test_count = 1 if config['SHOW_STEPS'][0] else 3
    
    for message in test_messages[:test_count]:
        try:
            encrypted = cipher.encrypt_message(message)
            print(f"'{message}' → {encrypted}")
                
        except Exception as e:
            print(f"'{message}' → ERROR: {e}")

print(f"\n{'='*70}")
print("CHACHA20 EDUCATIONAL DEMONSTRATIONS")
print('='*70)

# Create a demo cipher
demo_options = pd.DataFrame({
    'KEY': ['EDUCATE'],
    'NONCE': ['learn123'],
    'COUNTER': [0],
    'OUTPUT_FORMAT': ['HEX'],
    'SHOW_STEPS': [False]
})
demo_cipher = encrypt(None, demo_options)

# Demonstrate ChaCha20 internals
print("\n1. ChaCha20 Internal Operations:")
demo_cipher.demonstrate_chacha20_internals("HI")

print("\n" + "="*50)
print("2. Nonce Sensitivity Test:")
demo_cipher.test_nonce_sensitivity()

print("\n" + "="*50)
print("3. Block Structure:")
demo_cipher.show_block_structure()

print(f"\n{'='*70}")
print("CHACHA20 EDUCATIONAL SUMMARY")
print('='*70)
print("""
CHACHA20 ALGORITHM OVERVIEW:

1. INITIALIZATION:
- 256-bit key (always, derived if needed)
- 96-bit nonce (unique per encryption)
- 32-bit counter (allows 256GB per nonce)
- Constants: "expand 32-byte k"

2. STATE MATRIX (4×4 of 32-bit words):
[const][const][const][const]
[ key ][ key ][ key ][ key ]
[ key ][ key ][ key ][ key ]
[count][nonce][nonce][nonce]

3. BLOCK GENERATION:
- 10 double rounds (20 rounds total)
- Quarter-round function with ARX operations
- Add original state to final state
- Produces 64 bytes per block

4. QUARTER ROUND (a,b,c,d):
a += b; d ^= a; d <<<= 16;
c += d; b ^= c; b <<<= 12;
a += b; d ^= a; d <<<= 8;
c += d; b ^= c; b <<<= 7;

KEY ADVANTAGES:
✅ Excellent security (no known attacks)
✅ Very fast on all platforms
✅ Simple, elegant design
✅ Parallel processing friendly
✅ Random access to keystream
✅ Resistant to timing attacks
✅ Well-analyzed by cryptographers

MODERN USAGE:
- TLS 1.3 (preferred over AES)
- Google Chrome (QUIC protocol)
- SSH connections
- Signal messaging app
- Android disk encryption
- Many VPN implementations

WHY CHACHA20 SUCCEEDED:
- Conservative security margins
- Extensive cryptanalysis
- Efficient on mobile devices
- Simple implementation
- No known weaknesses

COMPARISON WITH PREDECESSORS:
- RC4: Completely replaced due to vulnerabilities
- Salsa20: ChaCha20 is the improved version
- AES: ChaCha20 often faster without hardware support
""")

