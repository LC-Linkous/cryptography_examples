import pandas as pd

def create_basic_latin_df():
    """
    Create a DataFrame for the Basic Latin Unicode block (U+0000 to U+007F)
    
    Returns:
        pandas.DataFrame: DataFrame with columns for code, glyph, decimal, octal, and ID
    """
    
    data = []
    
    # Basic Latin Unicode block ranges from U+0000 to U+007F (0-127 decimal)
    for i in range(128):
        # Unicode code point in hex format
        code = f"U+{i:04X}"
        
        # Decimal value
        decimal = i
        
        # Octal value
        octal = f"{i:03o}"
        
        # ID number (same as decimal in this case)
        id_num = i
        
        # Glyph - handle control characters and printable characters
        if i < 32:  # Control characters (0-31)
            # Common control character names
            control_names = {
                0: "NULL", 1: "SOH", 2: "STX", 3: "ETX", 4: "EOT", 5: "ENQ", 6: "ACK", 7: "BEL",
                8: "BS", 9: "TAB", 10: "LF", 11: "VT", 12: "FF", 13: "CR", 14: "SO", 15: "SI",
                16: "DLE", 17: "DC1", 18: "DC2", 19: "DC3", 20: "DC4", 21: "NAK", 22: "SYN", 23: "ETB",
                24: "CAN", 25: "EM", 26: "SUB", 27: "ESC", 28: "FS", 29: "GS", 30: "RS", 31: "US"
            }
            glyph = f"<{control_names.get(i, 'CTRL')}>"
        elif i == 32:  # Space character
            glyph = "<SPACE>"
        elif i == 127:  # DEL character
            glyph = "<DEL>"
        else:  # Printable characters (33-126)
            glyph = chr(i)
        
        data.append({
            'code': code,
            'glyph': glyph,
            'decimal': decimal,
            'octal': octal,
            'id': id_num
        })
    
    # Create DataFrame
    df = pd.DataFrame(data)
    
    return df

# Create the DataFrame
basic_latin_df = create_basic_latin_df()

# Display the DataFrame
print("Basic Latin Unicode Block (U+0000 to U+007F)")
print("=" * 50)
print(basic_latin_df.to_string(index=False))

# Display some basic info about the DataFrame
print(f"\nDataFrame shape: {basic_latin_df.shape}")
print(f"Columns: {list(basic_latin_df.columns)}")

# Show a sample of printable ASCII characters
print("\nSample of printable ASCII characters (decimal 65-90):")
print(basic_latin_df[(basic_latin_df['decimal'] >= 65) & (basic_latin_df['decimal'] <= 90)].to_string(index=False))