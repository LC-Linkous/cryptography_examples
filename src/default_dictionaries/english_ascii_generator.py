import numpy as np

def create_english_ascii_arrays():
    """
    Create NumPy arrays containing English ASCII characters
    
    Returns:
        dict: Dictionary containing different character arrays
    """
    
    # Method 1: Using chr() and range
    uppercase_letters = np.array([chr(i) for i in range(65, 91)])  # A-Z
    lowercase_letters = np.array([chr(i) for i in range(97, 123)])  # a-z
    
    # Method 2: Using string module (alternative approach)
    import string
    uppercase_string = np.array(list(string.ascii_uppercase))
    lowercase_string = np.array(list(string.ascii_lowercase))
    all_letters_string = np.array(list(string.ascii_letters))
    
    # Combined arrays
    all_letters = np.concatenate([uppercase_letters, lowercase_letters])
    
    # Alternative: all letters in alphabetical order (A-Z, then a-z)
    alphabetical_order = np.array([chr(i) for i in range(65, 91)] + [chr(i) for i in range(97, 123)])
    
    # Alternative: interleaved (Aa, Bb, Cc, etc.)
    interleaved = np.array([chr(65 + i) + chr(97 + i) for i in range(26)]).view('U1').reshape(-1)
    interleaved = interleaved[interleaved != '']  # Remove empty strings from view conversion
    
    # Just the basic array most people want
    english_ascii = np.array([chr(i) for i in range(65, 91)] + [chr(i) for i in range(97, 123)])
    
    return {
        'uppercase': uppercase_letters,
        'lowercase': lowercase_letters, 
        'all_letters': all_letters,
        'english_ascii': english_ascii,
        'alphabetical': alphabetical_order,
        'uppercase_string_method': uppercase_string,
        'lowercase_string_method': lowercase_string,
        'all_letters_string_method': all_letters_string
    }

# Create the arrays
arrays = create_english_ascii_arrays()

# Display the main array
print("=== English ASCII Characters Array ===")
english_ascii_chars = arrays['english_ascii']
print("Array:", english_ascii_chars)
print("Shape:", english_ascii_chars.shape)
print("Data type:", english_ascii_chars.dtype)
print("Total characters:", len(english_ascii_chars))

print("\n=== Uppercase Letters (A-Z) ===")
uppercase = arrays['uppercase']
print("Array:", uppercase)
print("Shape:", uppercase.shape)

print("\n=== Lowercase Letters (a-z) ===")
lowercase = arrays['lowercase']
print("Array:", lowercase)
print("Shape:", lowercase.shape)

print("\n=== All Letters Combined ===")
all_letters = arrays['all_letters']
print("Array:", all_letters)
print("Shape:", all_letters.shape)

# Show different ways to create the same array
print("\n=== Verification: Different Methods Give Same Result ===")
print("Method 1 (chr + range) uppercase == Method 2 (string module):", 
      np.array_equal(arrays['uppercase'], arrays['uppercase_string_method']))
print("Method 1 (chr + range) lowercase == Method 2 (string module):", 
      np.array_equal(arrays['lowercase'], arrays['lowercase_string_method']))

# Demonstrate array operations
print("\n=== Array Operations Examples ===")

# Find specific characters
print("Index of 'A':", np.where(english_ascii_chars == 'A')[0][0])
print("Index of 'z':", np.where(english_ascii_chars == 'z')[0][0])

# Boolean indexing
vowels_mask = np.isin(english_ascii_chars, ['A', 'E', 'I', 'O', 'U', 'a', 'e', 'i', 'o', 'u'])
vowels = english_ascii_chars[vowels_mask]
print("Vowels:", vowels)

# Get just uppercase or lowercase
is_uppercase = np.array([c.isupper() for c in english_ascii_chars])
is_lowercase = np.array([c.islower() for c in english_ascii_chars])

print("Uppercase characters:", english_ascii_chars[is_uppercase])
print("Lowercase characters:", english_ascii_chars[is_lowercase])

# Convert to ASCII codes
ascii_codes = np.array([ord(c) for c in english_ascii_chars])
print("ASCII codes:", ascii_codes)

print("\n=== Usage Examples ===")
print("""
# Simple array creation:
english_chars = np.array([chr(i) for i in range(65, 91)] + [chr(i) for i in range(97, 123)])

# Or using string module:
import string
english_chars = np.array(list(string.ascii_letters))

# Just uppercase:
uppercase = np.array([chr(i) for i in range(65, 91)])

# Just lowercase:
lowercase = np.array([chr(i) for i in range(97, 123)])

# Array operations:
vowels = english_chars[np.isin(english_chars, ['A', 'E', 'I', 'O', 'U', 'a', 'e', 'i', 'o', 'u'])]
ascii_codes = np.array([ord(c) for c in english_chars])
""")

# The main array you probably want:
print(f"\n=== MAIN RESULT ===")
print(f"english_ascii_chars = {repr(english_ascii_chars)}")