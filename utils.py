"""
Utility functions for ForgetYourpassword v4
"""

class SecureClipboard:
    """Simple clipboard operations"""

    @staticmethod
    def copy_password(password: str) -> bool:
        """Copy password to clipboard"""
        try:
            import pyperclip
            pyperclip.copy(password)
            return True
        except Exception:
            return False

    @staticmethod
    def clear_clipboard() -> None:
        """Clear clipboard"""
        try:
            import pyperclip
            pyperclip.copy("")
        except Exception:
            pass
