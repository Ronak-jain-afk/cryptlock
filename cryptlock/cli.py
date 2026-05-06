#!/usr/bin/env python3
"""CryptLock - Secure file and directory encryption CLI tool."""

import argparse
import os
import secrets
import shutil
import struct
import sys
import tempfile
import zipfile
from getpass import getpass

from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.constant_time import bytes_eq
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, DownloadColumn, TransferSpeedColumn, TimeRemainingColumn

# Initialize Rich Console
console = Console()

# Constants
SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
CHUNK_SIZE = 64 * 1024
KDF_ITERATIONS = 600_000
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536
ARGON2_PARALLELISM = 4
HEADER_VERSION = 2
MAGIC_BYTES = b"CRLK"


def derive_key(password: str, salt: bytes, version: int = HEADER_VERSION) -> bytes:
    """Derive a 256-bit key from password."""
    if version == 1:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=KDF_ITERATIONS,
        )
        return kdf.derive(password.encode("utf-8"))
    
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=32,
        type=Type.ID,
    )


def get_password(confirm: bool = False) -> str:
    """Get password from user with optional confirmation."""
    password = getpass("🔐 Enter password: ")
    if not password:
        raise ValueError("Password cannot be empty")
    
    if confirm:
        confirm_pass = getpass("🔐 Confirm password: ")
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
    """Attempt to securely delete a file."""
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
    """Encrypt a file or directory using AES-GCM and Argon2id."""
    original_path = os.path.abspath(filepath)
    is_dir = os.path.isdir(filepath)
    temp_zip = None

    if not os.path.exists(filepath):
        console.print(f"[bold red]Error:[/bold red] '{filepath}' does not exist")
        return

    try:
        password = get_password(confirm=True)
    except ValueError as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        return

    if is_dir:
        console.log("[cyan]Zipping directory...[/cyan]")
        temp_zip = zip_directory(filepath)
        filepath = temp_zip

    salt = secrets.token_bytes(SALT_SIZE)
    with console.status("[bold green]Deriving secure key...[/bold green]"):
        key = derive_key(password, salt, version=HEADER_VERSION)
    
    nonce_prefix = secrets.token_bytes(8)
    file_size = os.path.getsize(filepath)
    folder_name = os.path.basename(original_path) if is_dir else ""
    folder_name_bytes = folder_name.encode("utf-8")
    out_name = (original_path if is_dir else filepath) + ".enc"

    aesgcm = AESGCM(key)
    counter = 0

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        DownloadColumn(),
        TransferSpeedColumn(),
        TimeRemainingColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("[green]Encrypting...", total=file_size)
        with open(out_name, "wb") as out_f:
            out_f.write(MAGIC_BYTES)
            out_f.write(struct.pack("B", HEADER_VERSION))
            out_f.write(salt)
            out_f.write(nonce_prefix)
            out_f.write(struct.pack(">H", len(folder_name_bytes)))
            out_f.write(folder_name_bytes)
            with open(filepath, "rb") as in_f:
                while True:
                    chunk = in_f.read(CHUNK_SIZE)
                    if not chunk: break
                    chunk_nonce = nonce_prefix + struct.pack(">I", counter)
                    encrypted_chunk = aesgcm.encrypt(chunk_nonce, chunk, None)
                    out_f.write(encrypted_chunk)
                    counter += 1
                    progress.update(task, advance=len(chunk))

    console.print(Panel(f"[bold green]Success![/bold green] 🔐\nFile encrypted: [cyan]{out_name}[/cyan]", border_style="green"))

    if temp_zip:
        os.remove(temp_zip)
        shutil.rmtree(os.path.dirname(temp_zip), ignore_errors=True)

    if wipe:
        console.log("[yellow]Wiping original file(s)...[/yellow]")
        if is_dir: shutil.rmtree(original_path)
        else: secure_delete(original_path)


def decrypt_file(filepath: str, keep_encrypted: bool = False) -> None:
    """Decrypt an encrypted file or directory."""
    if not os.path.exists(filepath):
        console.print(f"[bold red]Error:[/bold red] '{filepath}' does not exist")
        return
    if not filepath.endswith(".enc"):
        console.print("[bold red]Error:[/bold red] File does not have .enc extension")
        return

    try:
        password = get_password(confirm=False)
    except ValueError as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        return

    try:
        with open(filepath, "rb") as f:
            magic = f.read(4)
            if magic != MAGIC_BYTES:
                console.print("[bold red]Error:[/bold red] Invalid file format")
                return
            version = struct.unpack("B", f.read(1))[0]
            if version > HEADER_VERSION:
                console.print(f"[bold red]Error:[/bold red] Unsupported version v{version}")
                return
            salt = f.read(SALT_SIZE)
            with console.status("[bold green]Deriving secure key...[/bold green]"):
                key = derive_key(password, salt, version=version)

            out_file = os.path.basename(filepath[:-4])
            temp_out = out_file + ".tmp"

            if version == 1:
                iv = f.read(16)
                signature = f.read(32)
                folder_name_len = struct.unpack(">H", f.read(2))[0]
                folder_name = f.read(folder_name_len).decode("utf-8") if folder_name_len > 0 else ""
                h = hmac.HMAC(key, hashes.SHA256())
                cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
                decryptor = cipher.decryptor()
                current_pos = f.tell()
                f.seek(0, os.SEEK_END)
                ciphertext_size = f.tell() - current_pos
                f.seek(current_pos)
                with Progress(console=console) as progress:
                    task = progress.add_task("[cyan]Decrypting (v1)...", total=ciphertext_size)
                    with open(temp_out, "wb") as out_f:
                        while True:
                            chunk = f.read(CHUNK_SIZE)
                            if not chunk: break
                            h.update(chunk)
                            out_f.write(decryptor.update(chunk))
                            progress.update(task, advance=len(chunk))
                        out_f.write(decryptor.finalize())
                if not bytes_eq(h.finalize(), signature):
                    console.print("[bold red]Error:[/bold red] Wrong password or file corrupted")
                    os.remove(temp_out)
                    return
            else:
                nonce_prefix = f.read(8)
                folder_name_len = struct.unpack(">H", f.read(2))[0]
                folder_name = f.read(folder_name_len).decode("utf-8") if folder_name_len > 0 else ""
                aesgcm = AESGCM(key)
                counter = 0
                GCM_CHUNK_SIZE = CHUNK_SIZE + 16
                current_pos = f.tell()
                f.seek(0, os.SEEK_END)
                data_size = f.tell() - current_pos
                f.seek(current_pos)
                with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), DownloadColumn(), TransferSpeedColumn(), TimeRemainingColumn(), console=console) as progress:
                    task = progress.add_task("[cyan]Decrypting (v2)...", total=data_size)
                    with open(temp_out, "wb") as out_f:
                        while True:
                            chunk = f.read(GCM_CHUNK_SIZE)
                            if not chunk: break
                            chunk_nonce = nonce_prefix + struct.pack(">I", counter)
                            try:
                                decrypted_chunk = aesgcm.decrypt(chunk_nonce, chunk, None)
                                out_f.write(decrypted_chunk)
                                counter += 1
                                progress.update(task, advance=len(chunk))
                            except Exception:
                                console.print("\n[bold red]Error:[/bold red] Wrong password or file corrupted")
                                out_f.close(); os.remove(temp_out); return

            os.replace(temp_out, out_file)
            if folder_name:
                console.log(f"[cyan]Extracting directory: {folder_name}[/cyan]")
                temp_zip = out_file + ".zip.tmp"
                if os.path.exists(temp_zip): os.remove(temp_zip)
                os.rename(out_file, temp_zip)
                try:
                    unzip_file(temp_zip, folder_name)
                    console.print(Panel(f"[bold green]Success![/bold green] 🔓\nDirectory restored: [cyan]{folder_name}[/cyan]", border_style="green"))
                finally:
                    if os.path.exists(temp_zip): os.remove(temp_zip)
            else:
                console.print(Panel(f"[bold green]Success![/bold green] 🔓\nFile decrypted: [cyan]{out_file}[/cyan]", border_style="green"))
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}"); return
    if not keep_encrypted:
        try: os.remove(filepath); console.log("[yellow]Encrypted file deleted[/yellow]")
        except Exception: pass


def main() -> None:
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        description="CryptLock - Secure file and directory encryption CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command")
    enc_parser = subparsers.add_parser("encrypt", help="Encrypt a file or directory")
    enc_parser.add_argument("file")
    enc_parser.add_argument("--wipe", "-w", action="store_true")
    dec_parser = subparsers.add_parser("decrypt", help="Decrypt an encrypted file")
    dec_parser.add_argument("file")
    dec_parser.add_argument("--keep", "-k", action="store_true")
    parser.add_argument("--version", "-v", action="version", version="CryptLock 2.0.0")

    args = parser.parse_args()
    if args.command == "encrypt": encrypt_file(args.file, wipe=args.wipe)
    elif args.command == "decrypt": decrypt_file(args.file, keep_encrypted=args.keep)
    else: parser.print_help()


if __name__ == "__main__":
    main()
