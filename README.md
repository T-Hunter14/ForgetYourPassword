# ForgetYourPassword (CLI)

A deterministic password generator that derives strong, repeatable passwords from a master key and user-defined keywords using PBKDF2-HMAC-SHA256, with a cross-platform hardware fingerprint available as the default master key source.
This CLI-only tool guides through selecting a master key, entering one or more keywords, choosing password length, and producing a visible password consistently for the same inputs.

### Features

- Deterministic passwords: same master key, same keywords, same length → same password output every time.
- PBKDF2-HMAC-SHA256 with 200,000 iterations for slow, brute-force-resistant derivation of key material.
- Character diversity and deterministic shuffle to include uppercase, lowercase, digits, and symbols in the final password.
- Default master key from hardware fingerprint (CPU id + motherboard serial) with cross-platform fallbacks when identifiers are unavailable.
- Simple interactive CLI flow with validation, sensible defaults, and the option to regenerate or exit.
- Optional clipboard utilities via pyperclip to copy and clear passwords if integrated into callers.

### How it works

- The core chooses a master key from either a hardware fingerprint or a provided manual string, then combines it with user keywords to feed the PBKDF2 derivation.
- Hardware fingerprinting concatenates available CPU and motherboard identifiers (or system info fallback) and hashes them with SHA-256, truncated to a 32-character hex string.
- The password generator maps the derived key bytes deterministically into mixed character sets, ensuring at least one from each set and performing a deterministic shuffle for stable results.

### Installation

- Requirements: Python 3.x, cryptography (for PBKDF2-HMAC-SHA256), and pyperclip optionally for clipboard helpers used by utilities.
- Install dependencies with pip: pip install cryptography pyperclip, using a virtual environment if preferred for isolation.

### Usage

- Run the CLI: python cli.py to start the interactive session in a terminal.
- Choose a master key source: default hardware fingerprint or a manual master key string provided at runtime.
- Enter one or more keywords (at least one required, up to a safety limit of 10), choose length between 8 and 128 with default 32, and generate the visible password.
- After generation, either produce another password with different inputs or exit via the simple menu.

### Example session

- Select option 1 for the default fingerprint, enter a few keywords like site and account, and press Enter to accept the default length of 32 for convenience.
- The CLI prints the final password and length, then offers options to generate again or exit based on preference.

### API usage

- Programmatic usage is available through PasswordCore to integrate deterministic password generation into other scripts or tools.
- It returns a result dict containing success, password, length, source, and keys_used for straightforward handling of outcomes.

```python
from core import PasswordCore

core = PasswordCore()
result = core.generate_password(
    master_key="",                 # leave empty when using default fingerprint
    user_keys=["site", "account"], # at least one keyword
    length=32,                     # 8..128
    use_default_fingerprint=True   # False to use manual master_key
)

if result["success"]:
    print(result["password"], result["length"], result["source"], result["keys_used"])
else:
    print("Error:", result["error"])
```

### OS notes

- Windows: CPU and motherboard identifiers are queried via wmic commands and combined into the fingerprint when available.
- Linux: Attempts dmidecode for the baseboard serial (may require sudo) and falls back to hostname if unavailable, while CPU info reads from /proc/cpuinfo.
- macOS: Uses sysctl for CPU brand string and system_profiler for the serial number to compose the fingerprint.

### Security notes

- A fixed salt is used to preserve determinism, meaning the same inputs always generate the same password; this is an intentional design trade-off for reproducibility.
- PBKDF2 with 200,000 iterations and SHA-256 slows brute force, while character set enforcement improves complexity and format diversity.
- Inputs are collected visibly in the CLI for simplicity, so avoid typing sensitive master keys in shared environments if using the manual option.

### Project structure

- cli.py: Interactive command-line interface orchestrating prompts and generation loop.
- core.py: Combines hardware fingerprinting and PBKDF2-based generation, validates inputs, and structures results.
- hardware_detector.py: Cross-platform CPU and motherboard identification with SHA-256-based fingerprinting and fallbacks.
- password_generator.py: PBKDF2-HMAC-SHA256 derivation, character mapping, and deterministic shuffling logic.
- utils.py: Optional clipboard helpers to copy or clear passwords via pyperclip.

### Assets

- Save this README as assets/README.md to keep documentation alongside other project resources and assets in the repository.
