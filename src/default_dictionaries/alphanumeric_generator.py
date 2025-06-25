import pandas as pd
import unicodedata

class AlphanumericUnicodeGenerator:
    """
    A class to generate DataFrames containing only alphanumeric Unicode characters
    """
    
    def __init__(self):
        self.max_unicode = 0x10FFFF
        # Unicode categories for letters and numbers
        self.letter_categories = {'Lu', 'Ll', 'Lt', 'Lm', 'Lo'}  # All letter categories
        self.number_categories = {'Nd', 'Nl', 'No'}  # All number categories
        self.alphanumeric_categories = self.letter_categories | self.number_categories
    
    def create_alphanumeric_df(self, start=0, end=0x10FFFF, max_chars=None):
        """
        Create a DataFrame with only alphanumeric characters from a Unicode range
        
        Args:
            start (int): Starting code point (decimal)
            end (int): Ending code point (decimal) 
            max_chars (int): Maximum number of characters to include (None for all)
            
        Returns:
            pandas.DataFrame: DataFrame with alphanumeric Unicode characters
        """
        data = []
        char_count = 0
        
        for i in range(start, min(end + 1, self.max_unicode + 1)):
            if max_chars and char_count >= max_chars:
                break
                
            try:
                char = chr(i)
                
                # Check if character is assigned and get its category
                try:
                    name = unicodedata.name(char)
                    category = unicodedata.category(char)
                    
                    # Only include alphanumeric characters
                    if category in self.alphanumeric_categories:
                        data.append({
                            'code': f"U+{i:04X}",
                            'glyph': char,
                            'decimal': i,
                            'octal': f"{i:o}",
                            'id': i,
                            'name': name,
                            'category': category,
                            'category_name': self._get_category_name(category),
                            'block': self._get_unicode_block(i),
                            'script': self._get_script_name(char)
                        })
                        char_count += 1
                        
                except ValueError:
                    # Unassigned character, skip
                    continue
                    
            except ValueError:
                # Invalid code point, skip
                continue
        
        return pd.DataFrame(data)
    
    def create_basic_alphanumeric_df(self):
        """Create DataFrame with basic ASCII alphanumeric characters (A-Z, a-z, 0-9)"""
        return self.create_alphanumeric_df(0, 127)
    
    def create_latin_alphanumeric_df(self):
        """Create DataFrame with Latin script alphanumeric characters"""
        return self.create_alphanumeric_df(0, 0x02FF)
    
    def create_alphanumeric_by_script(self, script_ranges):
        """
        Create DataFrame for specific script ranges
        
        Args:
            script_ranges (dict): Dictionary of script names and their ranges
            
        Returns:
            pandas.DataFrame: Combined DataFrame for all specified scripts
        """
        all_data = []
        
        for script_name, (start, end) in script_ranges.items():
            script_df = self.create_alphanumeric_df(start, end)
            all_data.append(script_df)
        
        if all_data:
            return pd.concat(all_data, ignore_index=True)
        else:
            return pd.DataFrame()
    
    def create_common_scripts_alphanumeric(self):
        """Create DataFrame with alphanumeric characters from common scripts"""
        script_ranges = {
            'Latin': (0x0000, 0x02FF),
            'Greek': (0x0370, 0x03FF),
            'Cyrillic': (0x0400, 0x04FF),
            'Arabic': (0x0600, 0x06FF),
            'Hebrew': (0x0590, 0x05FF),
            'Devanagari': (0x0900, 0x097F),
            'Bengali': (0x0980, 0x09FF),
            'Thai': (0x0E00, 0x0E7F),
            'Hiragana': (0x3040, 0x309F),
            'Katakana': (0x30A0, 0x30FF),
            'CJK': (0x4E00, 0x9FFF)
        }
        
        return self.create_alphanumeric_by_script(script_ranges)
    
    def _get_category_name(self, category):
        """Get human-readable category name"""
        category_names = {
            'Lu': 'Uppercase Letter',
            'Ll': 'Lowercase Letter', 
            'Lt': 'Titlecase Letter',
            'Lm': 'Modifier Letter',
            'Lo': 'Other Letter',
            'Nd': 'Decimal Number',
            'Nl': 'Letter Number',
            'No': 'Other Number'
        }
        return category_names.get(category, category)
    
    def _get_unicode_block(self, code_point):
        """Get Unicode block name for a code point"""
        blocks = [
            (0x0000, 0x007F, "Basic Latin"),
            (0x0080, 0x00FF, "Latin-1 Supplement"),
            (0x0100, 0x017F, "Latin Extended-A"),
            (0x0180, 0x024F, "Latin Extended-B"),
            (0x0250, 0x02AF, "IPA Extensions"),
            (0x02B0, 0x02FF, "Spacing Modifier Letters"),
            (0x0370, 0x03FF, "Greek and Coptic"),
            (0x0400, 0x04FF, "Cyrillic"),
            (0x0530, 0x058F, "Armenian"),
            (0x0590, 0x05FF, "Hebrew"),
            (0x0600, 0x06FF, "Arabic"),
            (0x0900, 0x097F, "Devanagari"),
            (0x0980, 0x09FF, "Bengali"),
            (0x0A00, 0x0A7F, "Gurmukhi"),
            (0x0A80, 0x0AFF, "Gujarati"),
            (0x0B00, 0x0B7F, "Oriya"),
            (0x0B80, 0x0BFF, "Tamil"),
            (0x0C00, 0x0C7F, "Telugu"),
            (0x0C80, 0x0CFF, "Kannada"),
            (0x0D00, 0x0D7F, "Malayalam"),
            (0x0E00, 0x0E7F, "Thai"),
            (0x0E80, 0x0EFF, "Lao"),
            (0x1000, 0x109F, "Myanmar"),
            (0x10A0, 0x10FF, "Georgian"),
            (0x3040, 0x309F, "Hiragana"),
            (0x30A0, 0x30FF, "Katakana"),
            (0x4E00, 0x9FFF, "CJK Unified Ideographs"),
            (0xAC00, 0xD7AF, "Hangul Syllables"),
            (0xFF00, 0xFFEF, "Halfwidth and Fullwidth Forms")
        ]
        
        for start, end, name in blocks:
            if start <= code_point <= end:
                return name
        return "Other"
    
    def _get_script_name(self, char):
        """Get script name for a character (simplified)"""
        code_point = ord(char)
        
        if 0x0000 <= code_point <= 0x02FF:
            return "Latin"
        elif 0x0370 <= code_point <= 0x03FF:
            return "Greek"
        elif 0x0400 <= code_point <= 0x04FF:
            return "Cyrillic"
        elif 0x0590 <= code_point <= 0x05FF:
            return "Hebrew"
        elif 0x0600 <= code_point <= 0x06FF:
            return "Arabic"
        elif 0x0900 <= code_point <= 0x097F:
            return "Devanagari"
        elif 0x3040 <= code_point <= 0x309F:
            return "Hiragana"
        elif 0x30A0 <= code_point <= 0x30FF:
            return "Katakana"
        elif 0x4E00 <= code_point <= 0x9FFF:
            return "Han"
        elif 0xAC00 <= code_point <= 0xD7AF:
            return "Hangul"
        else:
            return "Other"

# Create generator instance
alpha_gen = AlphanumericUnicodeGenerator()

# Example 1: Basic ASCII alphanumeric (A-Z, a-z, 0-9)
print("=== Basic ASCII Alphanumeric ===")
basic_df = alpha_gen.create_basic_alphanumeric_df()
print(basic_df)
print(f"Total characters: {len(basic_df)}")

# Example 2: Latin script alphanumeric (includes accented characters)
print("\n=== Latin Script Alphanumeric (first 20) ===")
latin_df = alpha_gen.create_latin_alphanumeric_df()
print(latin_df.head(20))
print(f"Total Latin alphanumeric characters: {len(latin_df)}")

# Example 3: Greek alphanumeric
print("\n=== Greek Alphanumeric ===")  
greek_df = alpha_gen.create_alphanumeric_df(0x0370, 0x03FF)
print(greek_df.head(10))
print(f"Total Greek alphanumeric characters: {len(greek_df)}")

# Example 4: Sample from common scripts (limited to 100 chars for display)
print("\n=== Sample from Common Scripts (first 50) ===")
common_df = alpha_gen.create_common_scripts_alphanumeric()
print(common_df.head(50))
print(f"Total characters from common scripts: {len(common_df)}")

# Example 5: Character distribution by category
print("\n=== Character Distribution by Category ===")
if len(common_df) > 0:
    category_counts = common_df['category_name'].value_counts()
    print(category_counts)

# Example 6: Character distribution by script
print("\n=== Character Distribution by Script ===")
if len(common_df) > 0:
    script_counts = common_df['script'].value_counts()
    print(script_counts)

print("\n=== Usage Examples ===")
print("""
# Get only ASCII alphanumeric:
ascii_df = alpha_gen.create_basic_alphanumeric_df()

# Get Latin script alphanumeric (includes accented letters):
latin_df = alpha_gen.create_latin_alphanumeric_df()

# Get alphanumeric from specific range:
greek_df = alpha_gen.create_alphanumeric_df(0x0370, 0x03FF)

# Get first 1000 alphanumeric characters:
sample_df = alpha_gen.create_alphanumeric_df(0, 0x10FFFF, max_chars=1000)

# Export to CSV:
df.to_csv('alphanumeric_unicode.csv', index=False)
""")