"""CryptLock - Secure file and directory encryption CLI tool."""

__version__ = "1.0.2"
__author__ = "Ronak Jain"
__license__ = "MIT"

from cryptlock.cli import encrypt_file, decrypt_file

__all__ = ["encrypt_file", "decrypt_file", "__version__"]

