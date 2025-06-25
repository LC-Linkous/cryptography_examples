import pandas as pd
import unicodedata
import sys

class UnicodeDataFrameGenerator:
    """
    A class to generate Unicode DataFrames for various ranges and categories
    """
    
    def __init__(self):
        self.max_unicode = 0x10FFFF  # Maximum Unicode code point
    
    def create_unicode_df(self, start=0, end=127, include_unassigned=False):
        """
        Create a DataFrame for a Unicode range
        
        Args:
            start (int): Starting code point (decimal)
            end (int): Ending code point (decimal)
            include_unassigned (bool): Whether to include unassigned code points
            
        Returns:
            pandas.DataFrame: DataFrame with Unicode character information
        """
        data = []
        
        for i in range(start, end + 1):
            try:
                # Get character
                char = chr(i)
                
                # Check if character is assigned
                try:
                    name = unicodedata.name(char)
                    is_assigned = True
                except ValueError:
                    name = "<UNASSIGNED>"
                    is_assigned = False
                
                # Skip unassigned characters if requested
                if not include_unassigned and not is_assigned:
                    continue
                
                # Unicode code point in hex format
                code = f"U+{i:04X}"
                
                # Get character properties
                category = unicodedata.category(char) if is_assigned else "Cn"
                
                # Glyph representation
                if category.startswith('C'):  # Control characters
                    if name != "<UNASSIGNED>":
                        glyph = f"<{name}>"
                    else:
                        glyph = "<UNASSIGNED>"
                elif i == 32:  # Space
                    glyph = "<SPACE>"
                elif unicodedata.category(char) in ['Zs', 'Zl', 'Zp']:  # Other spaces
                    glyph = f"<{name}>"
                else:
                    glyph = char
                
                data.append({
                    'code': code,
                    'glyph': glyph,
                    'decimal': i,
                    'octal': f"{i:o}",
                    'id': i,
                    'name': name,
                    'category': category,
                    'block': self._get_unicode_block(i)
                })
                
            except ValueError:
                # Skip invalid code points
                continue
        
        return pd.DataFrame(data)
    
    def create_unicode_block_df(self, block_name):
        """
        Create DataFrame for a specific Unicode block
        
        Args:
            block_name (str): Name of the Unicode block
            
        Returns:
            pandas.DataFrame: DataFrame for the specified block
        """
        blocks = {
            'basic_latin': (0x0000, 0x007F),
            'latin1_supplement': (0x0080, 0x00FF),
            'latin_extended_a': (0x0100, 0x017F),
            'latin_extended_b': (0x0180, 0x024F),
            'greek': (0x0370, 0x03FF),
            'cyrillic': (0x0400, 0x04FF),
            'arabic': (0x0600, 0x06FF),
            'cjk_unified_ideographs': (0x4E00, 0x9FFF),
            'hiragana': (0x3040, 0x309F),
            'katakana': (0x30A0, 0x30FF),
            'mathematical_operators': (0x2200, 0x22FF),
            'arrows': (0x2190, 0x21FF),
            'box_drawing': (0x2500, 0x257F),
            'geometric_shapes': (0x25A0, 0x25FF),
            'miscellaneous_symbols': (0x2600, 0x26FF),
            'dingbats': (0x2700, 0x27BF),
            'emoji': (0x1F600, 0x1F64F),  # Emoticons
        }
        
        block_name = block_name.lower().replace(' ', '_').replace('-', '_')
        
        if block_name not in blocks:
            available_blocks = ', '.join(blocks.keys())
            raise ValueError(f"Block '{block_name}' not found. Available blocks: {available_blocks}")
        
        start, end = blocks[block_name]
        return self.create_unicode_df(start, end, include_unassigned=False)
    
    def create_assigned_unicode_sample(self, sample_size=1000, start=0):
        """
        Create a sample of assigned Unicode characters
        
        Args:
            sample_size (int): Number of characters to include
            start (int): Starting code point
            
        Returns:
            pandas.DataFrame: Sample DataFrame
        """
        data = []
        current = start
        count = 0
        
        while count < sample_size and current <= self.max_unicode:
            try:
                char = chr(current)
                try:
                    name = unicodedata.name(char)
                    
                    # This is an assigned character
                    code = f"U+{current:04X}"
                    category = unicodedata.category(char)
                    
                    # Glyph representation
                    if category.startswith('C'):
                        glyph = f"<{name}>"
                    elif current == 32:
                        glyph = "<SPACE>"
                    elif category in ['Zs', 'Zl', 'Zp']:
                        glyph = f"<{name}>"
                    else:
                        glyph = char
                    
                    data.append({
                        'code': code,
                        'glyph': glyph,
                        'decimal': current,
                        'octal': f"{current:o}",
                        'id': current,
                        'name': name,
                        'category': category,
                        'block': self._get_unicode_block(current)
                    })
                    
                    count += 1
                    
                except ValueError:
                    # Unassigned character, skip
                    pass
                    
            except ValueError:
                # Invalid code point, skip
                pass
            
            current += 1
        
        return pd.DataFrame(data)
    
    def _get_unicode_block(self, code_point):
        """Get the Unicode block name for a code point"""
        # Simplified block detection - you could expand this
        if 0x0000 <= code_point <= 0x007F:
            return "Basic Latin"
        elif 0x0080 <= code_point <= 0x00FF:
            return "Latin-1 Supplement"
        elif 0x0100 <= code_point <= 0x017F:
            return "Latin Extended-A"
        elif 0x0180 <= code_point <= 0x024F:
            return "Latin Extended-B"
        elif 0x0370 <= code_point <= 0x03FF:
            return "Greek and Coptic"
        elif 0x0400 <= code_point <= 0x04FF:
            return "Cyrillic"
        elif 0x0600 <= code_point <= 0x06FF:
            return "Arabic"
        elif 0x4E00 <= code_point <= 0x9FFF:
            return "CJK Unified Ideographs"
        elif 0x1F600 <= code_point <= 0x1F64F:
            return "Emoticons"
        else:
            return "Other"

# Create generator instance
unicode_gen = UnicodeDataFrameGenerator()

# Example 1: Basic Latin block
print("=== Basic Latin Block ===")
basic_latin_df = unicode_gen.create_unicode_block_df('basic_latin')
print(basic_latin_df.head(10))
print(f"Shape: {basic_latin_df.shape}")

# Example 2: Greek block
print("\n=== Greek Block ===")
greek_df = unicode_gen.create_unicode_block_df('greek')
print(greek_df.head(10))
print(f"Shape: {greek_df.shape}")

# Example 3: Sample of assigned Unicode characters
print("\n=== Sample of Assigned Unicode Characters ===")
sample_df = unicode_gen.create_assigned_unicode_sample(50, start=0)
print(sample_df.head(10))

# Example 4: Custom range
print("\n=== Custom Range (Mathematical Operators) ===")
math_df = unicode_gen.create_unicode_df(0x2200, 0x22FF, include_unassigned=False)
print(math_df.head(10))
print(f"Shape: {math_df.shape}")

# Show available methods
print("\n=== Available Unicode Blocks ===")
available_blocks = [
    'basic_latin', 'latin1_supplement', 'latin_extended_a', 'latin_extended_b',
    'greek', 'cyrillic', 'arabic', 'cjk_unified_ideographs', 'hiragana', 
    'katakana', 'mathematical_operators', 'arrows', 'box_drawing', 
    'geometric_shapes', 'miscellaneous_symbols', 'dingbats', 'emoji'
]
print(', '.join(available_blocks))

print("\n=== Usage Examples ===")
print("""
# Create DataFrame for a specific block:
df = unicode_gen.create_unicode_block_df('greek')

# Create DataFrame for a custom range:
df = unicode_gen.create_unicode_df(0x2600, 0x26FF)  # Miscellaneous Symbols

# Get a sample of assigned Unicode characters:
df = unicode_gen.create_assigned_unicode_sample(1000, start=0x1000)

# Export to CSV:
df.to_csv('unicode_data.csv', index=False)
""")