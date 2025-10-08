"""
Hardware Fingerprint Detection

Detects unique hardware identifiers:
- CPU ID (processor identification)
- Motherboard Serial Number

Creates a SHA-256 hash fingerprint for deterministic password generation.
Cross-platform support: Windows, Linux, macOS.
"""

import platform
import subprocess
import hashlib
from typing import Optional


class HardwareDetector:
    """Cross-platform hardware fingerprint detector"""

    def __init__(self):
        """Initialize detector with current system type"""
        self.system = platform.system().lower()

    def get_default_fingerprint(self) -> str:
        """
        Generate unique hardware fingerprint

        Combines CPU ID and Motherboard Serial into a SHA-256 hash.
        Falls back to platform info if hardware IDs unavailable.

        Returns:
            str: 32-character hexadecimal fingerprint
        """
        identifiers = []

        # Get CPU identifier
        cpu_id = self._get_cpu_id()
        if cpu_id:
            identifiers.append(f"cpu:{cpu_id}")

        # Get Motherboard serial
        mb_serial = self._get_motherboard_serial()
        if mb_serial:
            identifiers.append(f"mb:{mb_serial}")

        # Fallback to system info if no hardware detected
        if not identifiers:
            system_info = f"sys:{platform.platform()}"
            identifiers.append(system_info)

        # Hash combined identifiers
        combined = "|".join(identifiers)
        return hashlib.sha256(combined.encode()).hexdigest()[:32]

    def _get_cpu_id(self) -> Optional[str]:
        """
        Get CPU processor ID

        Returns:
            Optional[str]: CPU identifier or None if unavailable
        """
        try:
            if self.system == "windows":
                # Windows: Use WMIC to get ProcessorId
                result = subprocess.run(
                    ["wmic", "cpu", "get", "ProcessorId", "/value"],
                    capture_output=True, text=True, timeout=10
                )
                for line in result.stdout.split("\n"):
                    if "ProcessorId=" in line:
                        return line.split("=")[1].strip()

            elif self.system == "linux":
                # Linux: Read from /proc/cpuinfo
                with open("/proc/cpuinfo", "r") as f:
                    for line in f:
                        if "processor" in line.lower() and ":" in line:
                            return line.split(":")[1].strip()

            elif self.system == "darwin":  # macOS
                # macOS: Use sysctl for CPU info
                result = subprocess.run(
                    ["sysctl", "-n", "machdep.cpu.brand_string"],
                    capture_output=True, text=True, timeout=10
                )
                return result.stdout.strip()

        except Exception:
            pass

        return None

    def _get_motherboard_serial(self) -> Optional[str]:
        """
        Get motherboard serial number

        Returns:
            Optional[str]: Motherboard serial or None if unavailable
        """
        try:
            if self.system == "windows":
                # Windows: Use WMIC to get baseboard serial
                result = subprocess.run(
                    ["wmic", "baseboard", "get", "SerialNumber", "/value"],
                    capture_output=True, text=True, timeout=10
                )
                for line in result.stdout.split("\n"):
                    if "SerialNumber=" in line:
                        return line.split("=")[1].strip()

            elif self.system == "linux":
                # Linux: Use dmidecode (requires sudo)
                try:
                    result = subprocess.run(
                        ["sudo", "dmidecode", "-s", "baseboard-serial-number"],
                        capture_output=True, text=True, timeout=10
                    )
                    return result.stdout.strip()
                except:
                    # Fallback to hostname
                    return platform.node()

            elif self.system == "darwin":  # macOS
                # macOS: Use system_profiler
                result = subprocess.run(
                    ["system_profiler", "SPHardwareDataType"],
                    capture_output=True, text=True, timeout=10
                )
                for line in result.stdout.split("\n"):
                    if "Serial Number" in line:
                        return line.split(":")[1].strip()

        except Exception:
            pass

        return None
