"""
Password Generator using PBKDF2-HMAC-SHA256

Implements deterministic password generation with:
- PBKDF2 key derivation (200,000 iterations)
- Character set diversity (uppercase, lowercase, digits, symbols)
- Deterministic shuffling for same input = same output
"""

import hashlib
from typing import List
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Configuration
DEFAULT_PBKDF2_ITERATIONS = 200000  # Strong security against brute force
DEFAULT_PASSWORD_LENGTH = 32

# Character sets for password generation
UPPERCASE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
LOWERCASE_CHARS = "abcdefghijklmnopqrstuvwxyz"
DIGIT_CHARS = "0123456789"
SYMBOL_CHARS = "!@#$%^&*()_+-=[]{}|;:,.<>?"


class PasswordGenerator:
    """Deterministic password generation using PBKDF2"""

    def generate_password(self,
                         master_key: str,
                         user_keys: List[str],
                         length: int = DEFAULT_PASSWORD_LENGTH) -> str:
        """
        Generate a deterministic password

        Args:
            master_key: The master key (fingerprint or manual)
            user_keys: List of user-defined keywords
            length: Desired password length

        Returns:
            str: Generated password with mixed character types
        """
        # Combine all inputs into single string
        combined_input = f"{master_key}|" + "|".join(user_keys)

        # Derive key material using PBKDF2
        key_material = self._generate_pbkdf2(combined_input)

        # Map key material to password characters
        return self._map_to_password(key_material, length)

    def _generate_pbkdf2(self, input_data: str) -> bytes:
        """
        Generate cryptographic key material using PBKDF2-HMAC-SHA256

        Args:
            input_data: Combined master key and user keys

        Returns:
            bytes: 64 bytes of key material
        """
        # Use fixed salt for determinism (same input = same output)
        salt = hashlib.sha256(b"ForgetYourpassword-v1-salt").digest()

        # Configure PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=64,  # 64 bytes of output
            salt=salt,
            iterations=DEFAULT_PBKDF2_ITERATIONS  # 200,000 iterations for security
        )

        return kdf.derive(input_data.encode())

    def _map_to_password(self, key_material: bytes, length: int) -> str:
        """
        Map key material bytes to password characters

        Ensures password contains at least one character from each set:
        - Uppercase letters
        - Lowercase letters
        - Digits
        - Symbols

        Args:
            key_material: Derived key material from PBKDF2
            length: Desired password length

        Returns:
            str: Generated password
        """
        # Define character sets
        char_sets = [
            UPPERCASE_CHARS,
            LOWERCASE_CHARS,
            DIGIT_CHARS,
            SYMBOL_CHARS
        ]

        all_chars = "".join(char_sets)
        password = []

        # Step 1: Ensure at least one character from each set
        key_index = 0
        for char_set in char_sets:
            if key_index < len(key_material):
                char_index = key_material[key_index] % len(char_set)
                password.append(char_set[char_index])
                key_index += 1

        # Step 2: Fill remaining positions from all characters
        while len(password) < length and key_index < len(key_material):
            char_index = key_material[key_index] % len(all_chars)
            password.append(all_chars[char_index])
            key_index += 1

        # Step 3: Extend key material if needed using hash chaining
        while len(password) < length:
            extended_key = hashlib.sha256(key_material + len(password).to_bytes(4, 'big')).digest()
            for byte_val in extended_key:
                if len(password) >= length:
                    break
                char_index = byte_val % len(all_chars)
                password.append(all_chars[char_index])

        # Step 4: Deterministic shuffle based on key material
        for i in range(len(password)):
            if i < len(key_material):
                j = key_material[i] % len(password)
                password[i], password[j] = password[j], password[i]

        return "".join(password[:length])
