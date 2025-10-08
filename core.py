"""
Core Password Generation Logic

Handles the main password generation workflow:
- Hardware fingerprint detection
- Deterministic password generation using PBKDF2
- Master key + user keys combination
"""

import sys
import os
sys.path.append(os.path.dirname(__file__))

from typing import List, Dict, Any
from hardware_detector import HardwareDetector
from password_generator import PasswordGenerator

# Default password length
DEFAULT_PASSWORD_LENGTH = 32


class PasswordCore:
    """Core password generation engine"""

    def __init__(self):
        """Initialize hardware detector and password generator"""
        self.hardware_detector = HardwareDetector()
        self.password_generator = PasswordGenerator()

    def get_default_fingerprint(self) -> str:
        """
        Get unique hardware fingerprint based on CPU and Motherboard

        Returns:
            str: SHA-256 hash of hardware identifiers (32 chars)
        """
        return self.hardware_detector.get_default_fingerprint()

    def generate_password(self,
                         master_key: str,
                         user_keys: List[str],
                         length: int = DEFAULT_PASSWORD_LENGTH,
                         use_default_fingerprint: bool = True) -> Dict[str, Any]:
        """
        Generate a deterministic password

        Args:
            master_key: User-provided master key (or empty if using fingerprint)
            user_keys: List of user-defined keywords
            length: Desired password length (8-128)
            use_default_fingerprint: Whether to use hardware fingerprint as master key

        Returns:
            Dict containing:
                - success: True if generation succeeded
                - password: Generated password string
                - length: Password length
                - source: 'default_fingerprint' or 'manual_master_key'
                - keys_used: Number of user keys used
        """
        try:
            # Validation
            if not master_key and not use_default_fingerprint:
                return {"success": False, "error": "Master key required"}

            if not user_keys:
                return {"success": False, "error": "At least one user key required"}

            # Choose master key source
            if use_default_fingerprint:
                final_master_key = self.get_default_fingerprint()
                source = "default_fingerprint"
            else:
                final_master_key = master_key
                source = "manual_master_key"

            # Generate password using PBKDF2
            password = self.password_generator.generate_password(
                final_master_key, user_keys, length
            )

            return {
                "success": True,
                "password": password,
                "length": len(password),
                "source": source,
                "keys_used": len(user_keys)
            }

        except Exception as e:
            return {"success": False, "error": str(e)}
