#!/usr/bin/env python3


import argparse
import os
import platform
import secrets
import shutil
import struct
import sys
import tempfile
import zipfile
from getpass import getpass

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.constant_time import bytes_eq
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from tqdm import tqdm


SALT_SIZE = 16
IV_SIZE = 16
HMAC_SIZE = 32
CHUNK_SIZE = 64 * 1024  
KDF_ITERATIONS = 600_000  
HEADER_VERSION = 1
MAGIC_BYTES = b"CRLK" 


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from password using PBKDF2-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))

def create_hmac(key: bytes, data: bytes) -> bytes:
    """Create HMAC-SHA256 for data integrity verification."""
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()


def verify_hmac(key: bytes, data: bytes, signature: bytes) -> bool:
    """Verify HMAC using constant-time comparison."""
    expected = create_hmac(key, data)
    return bytes_eq(expected, signature)


def get_password(confirm: bool = False) -> str:
    """Get password from user with optional confirmation."""
    password = getpass("Enter password: ")
    if not password:
        raise ValueError("Password cannot be empty")
    
    if confirm:
        confirm_pass = getpass("Confirm password: ")
        if password != confirm_pass:
            raise ValueError("Passwords do not match")
    
    return password


def zip_directory(folder: str) -> str:
    """Create a temporary zip archive of a directory."""
    temp_dir = tempfile.mkdtemp()
    base = os.path.join(temp_dir, "archive")
    zip_path = shutil.make_archive(base, "zip", folder)
    return zip_path


def unzip_file(zip_path: str, out_dir: str) -> None:
    """Extract a zip archive to the specified directory."""
    with zipfile.ZipFile(zip_path, "r") as zip_ref:
        zip_ref.extractall(out_dir)


def secure_delete(filepath: str, passes: int = 3) -> None:
    """
    Attempt to securely delete a file.
    
    WARNING: This is NOT cryptographically secure on:
    - SSDs (wear leveling)
    - Copy-on-write filesystems (btrfs, ZFS)
    - Journaling filesystems
    
    For true secure deletion, use full-disk encryption.
    """
    if not os.path.isfile(filepath):
        return
    
    size = os.path.getsize(filepath)
    
    try:
        with open(filepath, "r+b") as f:
            for _ in range(passes):
                f.seek(0)
                remaining = size
                while remaining > 0:
                    chunk_size = min(CHUNK_SIZE, remaining)
                    f.write(secrets.token_bytes(chunk_size))
                    remaining -= chunk_size
                f.flush()
                os.fsync(f.fileno())
    except (IOError, OSError):
        pass  
    
    os.remove(filepath)


def encrypt_file(filepath: str, wipe: bool = False) -> None:
    """Encrypt a file or directory."""
    original_path = os.path.abspath(filepath)
    is_dir = os.path.isdir(filepath)
    temp_zip = None

    if not os.path.exists(filepath):
        print(f"Error: '{filepath}' does not exist")
        return

    try:
        password = get_password(confirm=True)
    except ValueError as e:
        print(f"Error: {e}")
        return

    if is_dir:
        print("Zipping directory...")
        temp_zip = zip_directory(filepath)
        filepath = temp_zip

    salt = secrets.token_bytes(SALT_SIZE)
    key = derive_key(password, salt)
    iv = secrets.token_bytes(IV_SIZE)

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()

    file_size = os.path.getsize(filepath)
    
    
    folder_name = os.path.basename(original_path) if is_dir else ""
    folder_name_bytes = folder_name.encode("utf-8")
    

    if is_dir:
        out_name = original_path + ".enc"
    else:
        out_name = filepath + ".enc"

    
    encrypted_data = bytearray()
    
    with open(filepath, "rb") as f:
        for chunk in tqdm(
            iter(lambda: f.read(CHUNK_SIZE), b""),
            total=(file_size // CHUNK_SIZE) + 1,
            desc="Encrypting",
            unit="blocks",
        ):
            encrypted_data.extend(encryptor.update(chunk))
    
    encrypted_data.extend(encryptor.finalize())
    encrypted_bytes = bytes(encrypted_data)

    
    signature = create_hmac(key, encrypted_bytes)

    
    
    with open(out_name, "wb") as f:
        f.write(MAGIC_BYTES)
        f.write(struct.pack("B", HEADER_VERSION))
        f.write(salt)
        f.write(iv)
        f.write(signature)
        f.write(struct.pack(">H", len(folder_name_bytes)))  
        f.write(folder_name_bytes)
        f.write(encrypted_bytes)

    print(f"File encrypted: {out_name}")

    
    if temp_zip:
        os.remove(temp_zip)
        
        temp_dir = os.path.dirname(temp_zip)
        if os.path.isdir(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)

    if wipe:
        print("Wiping original file(s)...")
        if is_dir:
            shutil.rmtree(original_path)
        else:
            secure_delete(original_path)


def decrypt_file(filepath: str, keep_encrypted: bool = False) -> None:
    """Decrypt an encrypted file or directory."""
    if not os.path.exists(filepath):
        print(f"Error: '{filepath}' does not exist")
        return

    if not filepath.endswith(".enc"):
        print("Error: File does not have .enc extension")
        return

    try:
        password = get_password(confirm=False)
    except ValueError as e:
        print(f"Error: {e}")
        return

    try:
        with open(filepath, "rb") as f:
            
            magic = f.read(4)
            if magic != MAGIC_BYTES:
                print("Error: Invalid file format (not a CryptLock file)")
                return

            version = struct.unpack("B", f.read(1))[0]
            if version > HEADER_VERSION:
                print(f"Error: File encrypted with newer version (v{version})")
                return

            salt = f.read(SALT_SIZE)
            iv = f.read(IV_SIZE)
            signature = f.read(HMAC_SIZE)
            
            folder_name_len = struct.unpack(">H", f.read(2))[0]
            folder_name_bytes = f.read(folder_name_len)
            folder_name = folder_name_bytes.decode("utf-8") if folder_name_len > 0 else ""
            
            
            ciphertext = f.read()

        key = derive_key(password, salt)

        
        if not verify_hmac(key, ciphertext, signature):
            print("Error: Wrong password or file corrupted")
            return

        cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
        decryptor = cipher.decryptor()


        decrypted_chunks = []
        total_chunks = (len(ciphertext) // CHUNK_SIZE) + 1

        for i in tqdm(range(0, len(ciphertext), CHUNK_SIZE), 
                      total=total_chunks,
                      desc="Decrypting", 
                      unit="blocks"):
            chunk = ciphertext[i:i + CHUNK_SIZE]
            decrypted_chunks.append(decryptor.update(chunk))

        decrypted_chunks.append(decryptor.finalize())
        decrypted = b"".join(decrypted_chunks)


        out_file = os.path.basename(filepath[:-4])  

        with open(out_file, "wb") as f:
            f.write(decrypted)

        print(f"File decrypted: {out_file}")


        if out_file.endswith(".zip") and folder_name:
            print(f"Extracting directory: {folder_name}")
            unzip_file(out_file, folder_name)
            os.remove(out_file)
            print(f"Directory restored: {folder_name}")

        if not keep_encrypted:
            os.remove(filepath)
            print("Encrypted file deleted")

    except struct.error:
        print("Error: Invalid file format")
    except Exception as e:
        print(f"Error during decryption: {e}")


def main() -> None:
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        description="CryptLock - Secure file and directory encryption CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  cryptlock encrypt myfile.txt
  cryptlock encrypt myfile.txt --wipe
  cryptlock encrypt myfolder --wipe
  cryptlock decrypt myfile.txt.enc
  cryptlock decrypt myfile.txt.enc --keep
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")


    enc_parser = subparsers.add_parser("encrypt", help="Encrypt a file or directory")
    enc_parser.add_argument("file", help="File or directory to encrypt")
    enc_parser.add_argument(
        "--wipe",
        "-w",
        action="store_true",
        help="Securely delete original after encryption (best-effort)",
    )


    dec_parser = subparsers.add_parser("decrypt", help="Decrypt an encrypted file")
    dec_parser.add_argument("file", help="Encrypted file to decrypt (.enc)")
    dec_parser.add_argument(
        "--keep",
        "-k",
        action="store_true",
        help="Keep the encrypted file after decryption",
    )


    parser.add_argument(
        "--version",
        "-v",
        action="version",
        version="%(prog)s 1.1.1",
    )

    args = parser.parse_args()

    if args.command == "encrypt":
        encrypt_file(args.file, wipe=args.wipe)
    elif args.command == "decrypt":
        decrypt_file(args.file, keep_encrypted=args.keep)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
