def caesar_decrypt(ciphertext, shift):
    """
    Caesar cipher decryption function.

    This function decrypts text that has been encrypted using the Caesar cipher.
    It shifts uppercase letters backward by the specified shift amount and
    replaces any non-uppercase characters with underscores.

    Parameters:
        ciphertext (str): The encrypted text to be decrypted.
        shift (int): The number of positions that letters were shifted during encryption.

    Returns:
        str: The decrypted text with only uppercase letters and underscores.

    Examples:
        >>> caesar_decrypt("KHOOR", 3)
        'HELLO'
        >>> caesar_decrypt("GUHWPB@FN", 7)
        'DREAMH_CK'
    """
    decrypted = []
    for char in ciphertext:
        if 'A' <= char <= 'Z':
            decrypted_char = chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
        else:
            decrypted_char = '_'
        decrypted.append(decrypted_char)
    return ''.join(decrypted)

ciphertext = "EDVLF FUBSWR GUHDPKDFN"

decrypted_message = caesar_decrypt(ciphertext, 3)
print(f"DH{{{decrypted_message}}}")