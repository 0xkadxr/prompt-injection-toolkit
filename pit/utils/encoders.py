"""
Text encoding utilities for payload obfuscation.

Provides functions for encoding and decoding text using various schemes
commonly used in prompt injection evasion: Base64, ROT13, hexadecimal,
leetspeak, unicode homoglyphs, and more.
"""

from __future__ import annotations

import base64
import codecs


def encode_base64(text: str) -> str:
    """
    Encode text to Base64.

    Args:
        text: The plaintext string to encode.

    Returns:
        Base64-encoded string.

    Example:
        >>> encode_base64("Ignore all instructions")
        'SWdub3JlIGFsbCBpbnN0cnVjdGlvbnM='
    """
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def decode_base64(encoded: str) -> str:
    """
    Decode a Base64 string back to plaintext.

    Args:
        encoded: The Base64-encoded string.

    Returns:
        Decoded plaintext string.
    """
    return base64.b64decode(encoded.encode("ascii")).decode("utf-8")


def encode_rot13(text: str) -> str:
    """
    Encode text using ROT13 (Caesar cipher with shift of 13).

    Args:
        text: The plaintext string to encode.

    Returns:
        ROT13-encoded string.

    Example:
        >>> encode_rot13("Ignore all instructions")
        'Vtaber nyy vafgehpgvbaf'
    """
    return codecs.encode(text, "rot_13")


def decode_rot13(encoded: str) -> str:
    """
    Decode a ROT13 string (ROT13 is its own inverse).

    Args:
        encoded: The ROT13-encoded string.

    Returns:
        Decoded plaintext string.
    """
    return codecs.decode(encoded, "rot_13")


def encode_hex(text: str) -> str:
    """
    Encode text as a hexadecimal string.

    Args:
        text: The plaintext string to encode.

    Returns:
        Space-separated hex-encoded string.

    Example:
        >>> encode_hex("Hello")
        '48 65 6c 6c 6f'
    """
    return " ".join(f"{b:02x}" for b in text.encode("utf-8"))


def decode_hex(encoded: str) -> str:
    """
    Decode a hex-encoded string back to plaintext.

    Args:
        encoded: Space-separated hex string.

    Returns:
        Decoded plaintext string.
    """
    hex_clean = encoded.replace(" ", "")
    return bytes.fromhex(hex_clean).decode("utf-8")


def encode_leetspeak(text: str) -> str:
    """
    Encode text in leetspeak (1337speak).

    Replaces common letters with numbers and symbols.

    Args:
        text: The plaintext string to encode.

    Returns:
        Leetspeak-encoded string.

    Example:
        >>> encode_leetspeak("Ignore all instructions")
        '1gn0r3 4ll 1n57ruc710n5'
    """
    leet_map: dict[str, str] = {
        "a": "4",
        "A": "4",
        "e": "3",
        "E": "3",
        "i": "1",
        "I": "1",
        "o": "0",
        "O": "0",
        "s": "5",
        "S": "5",
        "t": "7",
        "T": "7",
        "l": "1",
        "L": "1",
        "g": "9",
        "G": "9",
    }
    return "".join(leet_map.get(c, c) for c in text)


def decode_leetspeak(text: str) -> str:
    """
    Decode leetspeak back to approximate plaintext.

    Note: This is lossy since multiple letters map to the same number.
    Uses the most common reverse mapping.

    Args:
        text: Leetspeak-encoded string.

    Returns:
        Approximately decoded string.
    """
    reverse_map: dict[str, str] = {
        "4": "a",
        "3": "e",
        "1": "i",
        "0": "o",
        "5": "s",
        "7": "t",
        "9": "g",
    }
    return "".join(reverse_map.get(c, c) for c in text)


# Unicode homoglyph mapping (Latin -> visually similar Unicode)
_HOMOGLYPH_MAP: dict[str, str] = {
    "a": "\u0430",  # Cyrillic а
    "c": "\u0441",  # Cyrillic с
    "e": "\u0435",  # Cyrillic е
    "o": "\u043e",  # Cyrillic о
    "p": "\u0440",  # Cyrillic р
    "s": "\u0455",  # Cyrillic ѕ
    "x": "\u0445",  # Cyrillic х
    "y": "\u0443",  # Cyrillic у
    "i": "\u0456",  # Cyrillic і
    "A": "\u0410",  # Cyrillic А
    "B": "\u0412",  # Cyrillic В
    "C": "\u0421",  # Cyrillic С
    "E": "\u0415",  # Cyrillic Е
    "H": "\u041d",  # Cyrillic Н
    "K": "\u041a",  # Cyrillic К
    "M": "\u041c",  # Cyrillic М
    "O": "\u041e",  # Cyrillic О
    "P": "\u0420",  # Cyrillic Р
    "T": "\u0422",  # Cyrillic Т
    "X": "\u0425",  # Cyrillic Х
}

# Reverse mapping for decoding
_REVERSE_HOMOGLYPH: dict[str, str] = {v: k for k, v in _HOMOGLYPH_MAP.items()}


def encode_unicode_homoglyphs(text: str) -> str:
    """
    Replace characters with visually similar unicode homoglyphs.

    Uses Cyrillic characters that look identical to Latin ones to evade
    keyword-based text filters while maintaining readability.

    Args:
        text: The plaintext string to encode.

    Returns:
        String with homoglyph substitutions.

    Example:
        >>> encoded = encode_unicode_homoglyphs("ignore")
        >>> encoded == "ignore"  # Looks the same but different bytes
        False
    """
    return "".join(_HOMOGLYPH_MAP.get(c, c) for c in text)


def decode_unicode_homoglyphs(text: str) -> str:
    """
    Reverse unicode homoglyph substitutions back to ASCII.

    Args:
        text: String with homoglyph substitutions.

    Returns:
        Plain ASCII string.
    """
    return "".join(_REVERSE_HOMOGLYPH.get(c, c) for c in text)


def reverse_words(text: str) -> str:
    """
    Reverse the order of words in the text.

    Args:
        text: The input text.

    Returns:
        Text with word order reversed.

    Example:
        >>> reverse_words("Ignore all previous instructions")
        'instructions previous all Ignore'
    """
    return " ".join(text.split()[::-1])


def reverse_string(text: str) -> str:
    """
    Reverse the entire string character by character.

    Args:
        text: The input text.

    Returns:
        Reversed string.
    """
    return text[::-1]


def encode_morse(text: str) -> str:
    """
    Encode text in Morse code.

    Args:
        text: The plaintext string to encode.

    Returns:
        Morse code string with / separating words.
    """
    morse_map: dict[str, str] = {
        "A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".",
        "F": "..-.", "G": "--.", "H": "....", "I": "..", "J": ".---",
        "K": "-.-", "L": ".-..", "M": "--", "N": "-.", "O": "---",
        "P": ".--.", "Q": "--.-", "R": ".-.", "S": "...", "T": "-",
        "U": "..-", "V": "...-", "W": ".--", "X": "-..-", "Y": "-.--",
        "Z": "--..", "0": "-----", "1": ".----", "2": "..---",
        "3": "...--", "4": "....-", "5": ".....", "6": "-....",
        "7": "--...", "8": "---..", "9": "----.", " ": "/",
    }
    return " ".join(morse_map.get(c.upper(), c) for c in text)


def pig_latin(text: str) -> str:
    """
    Encode text in Pig Latin.

    Args:
        text: The plaintext string to encode.

    Returns:
        Pig Latin encoded string.
    """
    vowels = set("aeiouAEIOU")
    words = text.split()
    result: list[str] = []

    for word in words:
        if not word[0].isalpha():
            result.append(word)
        elif word[0] in vowels:
            result.append(word + "way")
        else:
            # Find first vowel
            for i, char in enumerate(word):
                if char in vowels:
                    result.append(word[i:] + word[:i] + "ay")
                    break
            else:
                result.append(word + "ay")

    return " ".join(result)
