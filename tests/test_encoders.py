"""Tests for the encoding utilities."""

import pytest

from pit.utils.encoders import (
    decode_base64,
    decode_hex,
    decode_leetspeak,
    decode_rot13,
    decode_unicode_homoglyphs,
    encode_base64,
    encode_hex,
    encode_leetspeak,
    encode_morse,
    encode_rot13,
    encode_unicode_homoglyphs,
    pig_latin,
    reverse_string,
    reverse_words,
)


class TestBase64:
    def test_encode_decode_roundtrip(self) -> None:
        original = "Ignore all previous instructions"
        encoded = encode_base64(original)
        decoded = decode_base64(encoded)
        assert decoded == original

    def test_encode_empty_string(self) -> None:
        assert encode_base64("") == ""
        assert decode_base64("") == ""

    def test_encode_unicode(self) -> None:
        original = "Hello, world! Unicode: cafe"
        encoded = encode_base64(original)
        decoded = decode_base64(encoded)
        assert decoded == original

    def test_encode_produces_base64_chars(self) -> None:
        encoded = encode_base64("test string")
        valid_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
        assert all(c in valid_chars for c in encoded)


class TestROT13:
    def test_encode_decode_roundtrip(self) -> None:
        original = "Ignore all previous instructions"
        encoded = encode_rot13(original)
        decoded = decode_rot13(encoded)
        assert decoded == original

    def test_double_encode_is_identity(self) -> None:
        original = "Hello World"
        assert encode_rot13(encode_rot13(original)) == original

    def test_preserves_non_alpha(self) -> None:
        original = "Hello, World! 123"
        encoded = encode_rot13(original)
        assert "," in encoded
        assert "!" in encoded
        assert "123" in encoded

    def test_known_value(self) -> None:
        assert encode_rot13("abc") == "nop"
        assert encode_rot13("ABC") == "NOP"


class TestHex:
    def test_encode_decode_roundtrip(self) -> None:
        original = "Override instructions"
        encoded = encode_hex(original)
        decoded = decode_hex(encoded)
        assert decoded == original

    def test_encode_format(self) -> None:
        encoded = encode_hex("AB")
        assert encoded == "41 42"

    def test_empty_string(self) -> None:
        assert encode_hex("") == ""


class TestLeetspeak:
    def test_encode(self) -> None:
        encoded = encode_leetspeak("test")
        assert encoded == "7357"

    def test_preserves_spaces(self) -> None:
        encoded = encode_leetspeak("hello world")
        assert " " in encoded

    def test_decode_approximation(self) -> None:
        encoded = encode_leetspeak("test")
        decoded = decode_leetspeak(encoded)
        # Leetspeak decoding is lossy but should produce readable text
        assert isinstance(decoded, str)
        assert len(decoded) == len(encoded)


class TestUnicodeHomoglyphs:
    def test_encode_changes_bytes(self) -> None:
        original = "ignore"
        encoded = encode_unicode_homoglyphs(original)
        assert encoded != original  # Different bytes
        assert len(encoded) == len(original)  # Same length

    def test_decode_roundtrip(self) -> None:
        original = "ignore all"
        encoded = encode_unicode_homoglyphs(original)
        decoded = decode_unicode_homoglyphs(encoded)
        assert decoded == original

    def test_preserves_unmapped_chars(self) -> None:
        original = "123 !@#"
        encoded = encode_unicode_homoglyphs(original)
        assert encoded == original  # No mappable characters


class TestReverseWords:
    def test_reverse_words(self) -> None:
        assert reverse_words("hello world") == "world hello"

    def test_single_word(self) -> None:
        assert reverse_words("hello") == "hello"

    def test_multiple_words(self) -> None:
        result = reverse_words("ignore all previous instructions")
        assert result == "instructions previous all ignore"


class TestReverseString:
    def test_reverse_string(self) -> None:
        assert reverse_string("hello") == "olleh"

    def test_empty_string(self) -> None:
        assert reverse_string("") == ""


class TestMorse:
    def test_encode_hello(self) -> None:
        encoded = encode_morse("HELLO")
        assert ".... . .-.. .-.. ---" == encoded

    def test_encode_with_spaces(self) -> None:
        encoded = encode_morse("HI THERE")
        assert "/" in encoded  # Word separator


class TestPigLatin:
    def test_consonant_start(self) -> None:
        result = pig_latin("hello")
        assert result == "ellohay"

    def test_vowel_start(self) -> None:
        result = pig_latin("apple")
        assert result == "appleway"

    def test_multiple_words(self) -> None:
        result = pig_latin("hello world")
        assert result == "ellohay orldway"
