"""
ForgetYourPassword v1 - CLI Only Version
Deterministic Password Generator

A simple command-line tool that generates strong, unique passwords
deterministically from a master key and user-defined keywords.
Uses PBKDF2-HMAC-SHA256 for secure password derivation.
"""

import sys
import os
sys.path.append(os.path.dirname(__file__))

from typing import List
from core import PasswordCore


class PasswordCLI:
    """Command-line interface for password generation"""

    def __init__(self):
        """Initialize the CLI with password generation core"""
        self.core = PasswordCore()

    def clear_screen(self):
        """Clear the terminal screen for better UX"""
        os.system('cls' if os.name == 'nt' else 'clear')

    def print_header(self):
        """Display application header"""
        print("=" * 50)
        print("  🔐 ForgetYourPassword v1 - CLI")
        print("  Deterministic Password Generator")
        print("=" * 50)
        print()

    def get_master_key_choice(self) -> tuple:
        """
        Prompt user to choose master key method

        Returns:
            tuple: (choice_type, manual_key) where choice_type is 'default' or 'manual'
        """
        print("Master Key Options:")
        print("1. Use Default Fingerprint (CPU + Motherboard)")
        print("2. Use Manual Master Key")
        print()

        while True:
            choice = input("Choose option (1 or 2): ").strip()

            if choice == "1":
                return "default", ""

            elif choice == "2":
                print("\nEnter manual master key (press Enter to cancel):")
                manual_key = input("Manual key: ").strip()

                # Allow user to cancel and go back to menu
                if not manual_key:
                    print("❌ Cancelled - going back to menu")
                    continue

                return "manual", manual_key

            elif choice == "":
                # Default to option 1 when pressing Enter
                print("Using default option (1)")
                return "default", ""

            else:
                print("❌ Invalid choice! Please enter 1 or 2 (or press Enter for default)")

    def get_user_keys(self) -> List[str]:
        """
        Prompt user to enter multiple keys
        User can press Enter on empty line to finish

        Returns:
            List[str]: List of user-provided keys (at least 1 required)
        """
        print("\nUser Keys:")
        print("Enter your keys one by one (visible)")
        print("Press Enter on empty line to finish")
        print()

        keys = []
        key_num = 1

        while True:
            key = input(f"Key {key_num}: ").strip()

            # Empty input terminates key entry
            if not key:
                if keys:  # At least one key was entered
                    print(f"\n⏹️ Finished - {len(keys)} keys entered")
                    break
                else:  # No keys entered yet - require at least one
                    print("❌ Need at least one key! Try again or Ctrl+C to exit")
                    continue

            keys.append(key)
            key_num += 1

            # Safety limit to prevent excessive keys
            if key_num > 10:
                print("\n⚠️ Maximum 10 keys reached!")
                break

        print(f"✅ {len(keys)} keys ready!")
        return keys

    def get_password_length(self) -> int:
        """
        Prompt user for desired password length

        Returns:
            int: Password length (8-128, default 32)
        """
        print("\nPassword Length:")
        print("Enter length (8-128) or press Enter for default (32):")

        while True:
            length_input = input("Length: ").strip()

            # Default to 32 if Enter is pressed
            if not length_input:
                print("Using default length: 32")
                return 32

            try:
                length = int(length_input)
                if 8 <= length <= 128:
                    return length
                else:
                    print("❌ Length must be between 8 and 128! Try again or press Enter for default")
            except ValueError:
                print("❌ Please enter a valid number! Try again or press Enter for default")

    def display_password(self, password: str):
        """
        Display the generated password (always visible)

        Args:
            password: The generated password
        """
        print("\n" + "=" * 50)
        print("  🎉 PASSWORD GENERATED")
        print("=" * 50)
        print()
        print(f"Password: {password}")
        print(f"Length: {len(password)} characters")
        print()
        print("=" * 50)

    def show_password_menu(self, password: str):
        """
        Display password and menu options

        Args:
            password: The generated password

        Returns:
            str: Action to take ('generate' or 'exit')
        """
        self.display_password(password)
        print()
        print("Options:")
        print("1. Generate new password")
        print("2. Exit")
        print("Press Enter for option 1 (Generate new)")
        print()

        while True:
            choice = input("Choose option (1-2): ").strip()

            # Default to "generate new" when pressing Enter
            if not choice or choice == "1":
                return "generate"

            elif choice == "2":
                return "exit"

            else:
                print("❌ Invalid choice! Enter 1-2 or press Enter for new password")

    def run(self):
        """Main CLI loop"""
        self.clear_screen()

        # Welcome message
        print("Welcome! Press Enter to start...")
        input()

        while True:
            self.print_header()

            try:
                # Step 1: Get master key choice
                master_choice, manual_key = self.get_master_key_choice()

                # Step 2: Get user keys
                user_keys = self.get_user_keys()

                # Step 3: Get password length
                length = self.get_password_length()

                # Step 4: Generate password
                print("\n🔄 Generating password...")

                use_default = master_choice == "default"
                result = self.core.generate_password(
                    manual_key if not use_default else "",
                    user_keys,
                    length,
                    use_default
                )

                if result["success"]:
                    # Step 5: Show password and menu
                    action = self.show_password_menu(result["password"])

                    if action == "exit":
                        break
                    elif action == "generate":
                        continue  # Generate new password
                else:
                    print(f"\n❌ Error: {result['error']}")
                    input("Press Enter to try again...")

            except KeyboardInterrupt:
                print("\n\n👋 Goodbye!")
                break

            except Exception as e:
                print(f"\n❌ Unexpected error: {e}")
                input("Press Enter to continue...")

        print("\nThank you for using ForgetYourPassword!")


def main():
    """Main entry point for the CLI application"""
    cli = PasswordCLI()
    cli.run()


if __name__ == "__main__":
    main()
