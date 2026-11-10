import hashlib
import os
from typing import Dict, Optional


class FileHasher:
    """
    Computes cryptographic hashes (SHA-256) of executable binaries with
    internal in-memory caching to avoid redundant disk I/O.
    """

    def __init__(self) -> None:
        self._cache: Dict[str, str] = {}

    def calculate_hash(self, file_path: Optional[str]) -> str:
        """
        Calculates the SHA-256 hash for a given binary file path.
        Returns the hex digest, or a status string on failure.
        """
        if not file_path:
            return ""

        if file_path in self._cache:
            return self._cache[file_path]

        try:
            if not os.path.exists(file_path):
                return ""

            with open(file_path, "rb") as f:
                sha256 = hashlib.file_digest(f, "sha256")
                digest = sha256.hexdigest()
                self._cache[file_path] = digest
                return digest
        except FileNotFoundError:
            return "file_not_found"
        except PermissionError:
            return "permission_denied"
        except Exception:
            return "unknown_error"

    def clear_cache(self) -> None:
        """Clears the internal hash cache."""
        self._cache.clear()