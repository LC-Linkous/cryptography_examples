import pandas as pd

class ASCIIDataFrameGenerator:
    """
    A class to generate DataFrames for ASCII characters (0-127)
    """
    
    def __init__(self):
        # ASCII control character names
        self.control_names = {
            0: "NULL", 1: "SOH", 2: "STX", 3: "ETX", 4: "EOT", 5: "ENQ", 6: "ACK", 7: "BEL",
            8: "BS", 9: "TAB", 10: "LF", 11: "VT", 12: "FF", 13: "CR", 14: "SO", 15: "SI",
            16: "DLE", 17: "DC1", 18: "DC2", 19: "DC3", 20: "DC4", 21: "NAK", 22: "SYN", 23: "ETB",
            24: "CAN", 25: "EM", 26: "SUB", 27: "ESC", 28: "FS", 29: "GS", 30: "RS", 31: "US",
            127: "DEL"
        }
        
        # ASCII character categories
        self.ascii_categories = {
            "control": list(range(0, 32)) + [127],
            "space": [32],
            "digits": list(range(48, 58)),  # 0-9
            "uppercase": list(range(65, 91)),  # A-Z
            "lowercase": list(range(97, 123)),  # a-z
            "punctuation": [33, 34, 39, 44, 45, 46, 47, 58, 59, 63],  # !"',-./:;?
            "symbols": [35, 36, 37, 38, 40, 41, 42, 43, 60, 61, 62, 64, 91, 92, 93, 94, 95, 96, 123, 124, 125, 126]  # Various symbols
        }
    
    def create_full_ascii_df(self):
        """Create DataFrame with all ASCII characters (0-127)"""
        data = []
        
        for i in range(128):
            # Determine category
            category = self._get_ascii_category(i)
            
            # Create glyph representation
            if i in self.control_names:
                glyph = f"<{self.control_names[i]}>"
            elif i == 32:
                glyph = "<SPACE>"
            else:
                glyph = chr(i)
            
            # Get character name/description
            name = self._get_ascii_name(i)
            
            data.append({
                'code': f"U+{i:04X}",
                'glyph': glyph,
                'decimal': i,
                'octal': f"{i:03o}",
                'hex': f"{i:02X}",
                'binary': f"{i:08b}",
                'id': i,
                'name': name,
                'category': category,
                'printable': i >= 32 and i <= 126,
                'alphanumeric': (48 <= i <= 57) or (65 <= i <= 90) or (97 <= i <= 122),
                'letter': (65 <= i <= 90) or (97 <= i <= 122),
                'digit': 48 <= i <= 57
            })
        
        return pd.DataFrame(data)
    
    def create_printable_ascii_df(self):
        """Create DataFrame with only printable ASCII characters (32-126)"""
        full_df = self.create_full_ascii_df()
        return full_df[full_df['printable'] == True].reset_index(drop=True)
    
    def create_alphanumeric_ascii_df(self):
        """Create DataFrame with only alphanumeric ASCII characters (A-Z, a-z, 0-9)"""
        full_df = self.create_full_ascii_df()
        return full_df[full_df['alphanumeric'] == True].reset_index(drop=True)
    
    def create_ascii_by_category(self, categories):
        """
        Create DataFrame for specific ASCII categories
        
        Args:
            categories (list): List of category names
            
        Returns:
            pandas.DataFrame: Filtered DataFrame
        """
        full_df = self.create_full_ascii_df()
        
        if isinstance(categories, str):
            categories = [categories]
        
        filtered_df = full_df[full_df['category'].isin(categories)].reset_index(drop=True)
        return filtered_df
    
    def create_control_characters_df(self):
        """Create DataFrame with ASCII control characters (0-31, 127)"""
        return self.create_ascii_by_category('control')
    
    def create_letters_df(self):
        """Create DataFrame with ASCII letters only (A-Z, a-z)"""
        full_df = self.create_full_ascii_df()
        return full_df[full_df['letter'] == True].reset_index(drop=True)
    
    def create_digits_df(self):
        """Create DataFrame with ASCII digits only (0-9)"""
        full_df = self.create_full_ascii_df()
        return full_df[full_df['digit'] == True].reset_index(drop=True)
    
    def _get_ascii_category(self, code):
        """Get the category for an ASCII character"""
        for category, codes in self.ascii_categories.items():
            if code in codes:
                return category
        return "other"
    
    def _get_ascii_name(self, code):
        """Get the name/description for an ASCII character"""
        if code in self.control_names:
            return self.control_names[code]
        elif code == 32:
            return "SPACE"
        elif 48 <= code <= 57:
            return f"DIGIT {chr(code)}"
        elif 65 <= code <= 90:
            return f"LATIN CAPITAL LETTER {chr(code)}"
        elif 97 <= code <= 122:
            return f"LATIN SMALL LETTER {chr(code)}"
        else:
            # For punctuation and symbols, provide descriptive names
            symbol_names = {
                33: "EXCLAMATION MARK", 34: "QUOTATION MARK", 35: "NUMBER SIGN",
                36: "DOLLAR SIGN", 37: "PERCENT SIGN", 38: "AMPERSAND", 39: "APOSTROPHE",
                40: "LEFT PARENTHESIS", 41: "RIGHT PARENTHESIS", 42: "ASTERISK", 43: "PLUS SIGN",
                44: "COMMA", 45: "HYPHEN-MINUS", 46: "FULL STOP", 47: "SOLIDUS",
                58: "COLON", 59: "SEMICOLON", 60: "LESS-THAN SIGN", 61: "EQUALS SIGN",
                62: "GREATER-THAN SIGN", 63: "QUESTION MARK", 64: "COMMERCIAL AT",
                91: "LEFT SQUARE BRACKET", 92: "REVERSE SOLIDUS", 93: "RIGHT SQUARE BRACKET",
                94: "CIRCUMFLEX ACCENT", 95: "LOW LINE", 96: "GRAVE ACCENT",
                123: "LEFT CURLY BRACKET", 124: "VERTICAL LINE", 125: "RIGHT CURLY BRACKET",
                126: "TILDE"
            }
            return symbol_names.get(code, f"CHARACTER {code}")

# Create generator instance
ascii_gen = ASCIIDataFrameGenerator()

# Example 1: Full ASCII table
print("=== Complete ASCII Table ===")
ascii_df = ascii_gen.create_full_ascii_df()
print(ascii_df.head(20))
print(f"Total ASCII characters: {len(ascii_df)}")

# Example 2: Only printable ASCII characters
print("\n=== Printable ASCII Characters (first 20) ===")
printable_df = ascii_gen.create_printable_ascii_df()
print(printable_df.head(20))
print(f"Total printable ASCII characters: {len(printable_df)}")

# Example 3: Only alphanumeric ASCII
print("\n=== Alphanumeric ASCII Characters ===")
alphanum_df = ascii_gen.create_alphanumeric_ascii_df()
print(alphanum_df)
print(f"Total alphanumeric ASCII characters: {len(alphanum_df)}")

# Example 4: ASCII letters only
print("\n=== ASCII Letters Only ===")
letters_df = ascii_gen.create_letters_df()
print(letters_df.head(10))
print(f"Total ASCII letters: {len(letters_df)}")

# Example 5: ASCII digits only
print("\n=== ASCII Digits Only ===")
digits_df = ascii_gen.create_digits_df()
print(digits_df)

# Example 6: Control characters
print("\n=== ASCII Control Characters (first 10) ===")
control_df = ascii_gen.create_control_characters_df()
print(control_df.head(10))
print(f"Total control characters: {len(control_df)}")

# Example 7: Character distribution by category
print("\n=== ASCII Character Distribution by Category ===")
category_counts = ascii_df['category'].value_counts()
print(category_counts)

# Example 8: Some interesting subsets
print("\n=== Uppercase Letters ===")
uppercase_df = ascii_gen.create_ascii_by_category('uppercase')
print(f"Characters: {''.join(uppercase_df['glyph'].tolist())}")

print("\n=== Lowercase Letters ===")
lowercase_df = ascii_gen.create_ascii_by_category('lowercase')
print(f"Characters: {''.join(lowercase_df['glyph'].tolist())}")

print("\n=== Punctuation ===")
punct_df = ascii_gen.create_ascii_by_category('punctuation')
print(f"Characters: {''.join(punct_df['glyph'].tolist())}")

print("\n=== Usage Examples ===")
print("""
# Get complete ASCII table:
ascii_df = ascii_gen.create_full_ascii_df()

# Get only printable characters (space through ~):
printable_df = ascii_gen.create_printable_ascii_df()

# Get only letters and numbers:
alphanum_df = ascii_gen.create_alphanumeric_ascii_df()

# Get specific categories:
letters_df = ascii_gen.create_letters_df()
digits_df = ascii_gen.create_digits_df()
control_df = ascii_gen.create_control_characters_df()

# Get multiple categories:
symbols_punct = ascii_gen.create_ascii_by_category(['symbols', 'punctuation'])

# Export to CSV:
ascii_df.to_csv('ascii_table.csv', index=False)

# Filter examples:
uppercase_only = ascii_df[ascii_df['category'] == 'uppercase']
printable_only = ascii_df[ascii_df['printable'] == True]
alphanumeric_only = ascii_df[ascii_df['alphanumeric'] == True]
""")