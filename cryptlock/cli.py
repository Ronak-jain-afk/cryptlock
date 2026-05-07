#!/usr/bin/env python3
"""CryptLock - Secure file and directory encryption CLI tool."""

import argparse
import json
import os
import secrets
import shutil
import struct
import sys
import tempfile
import zipfile
from datetime import datetime
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
from rich.table import Table

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
HEADER_VERSION = 4
MAGIC_BYTES = b"CRLK"

# Flags
FLAG_NONE = 0
FLAG_SELF_DESTRUCT = 1


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

    # Argon2id for v2, v3, and v4
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


def encrypt_file(filepath: str, keep_original: bool = False, self_destruct: bool = False, hide_image: str = None, note: str = None, in_place: bool = False) -> str:
    """Encrypt a file or directory using AES-GCM and Argon2id."""
    original_path = os.path.abspath(filepath)
    is_dir = os.path.isdir(filepath)
    temp_zip = None

    if not os.path.exists(filepath):
        console.print(f"[bold red]Error:[/bold red] '{filepath}' does not exist")
        return None

    if hide_image and not os.path.exists(hide_image):
        console.print(f"[bold red]Error:[/bold red] Image file '{hide_image}' does not exist")
        return None

    try:
        password = get_password(confirm=True)
    except ValueError as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        return None

    if is_dir:
        console.log("[cyan]Zipping directory...[/cyan]")
        temp_zip = zip_directory(filepath)
        filepath = temp_zip

    salt = secrets.token_bytes(SALT_SIZE)
    with console.status("[bold green]Deriving secure key...[/bold green]"):
        key = derive_key(password, salt, version=HEADER_VERSION)
    
    nonce_prefix = secrets.token_bytes(8)
    file_size = os.path.getsize(filepath)
    
    # Prepare Metadata
    metadata = {
        "filename": os.path.basename(original_path),
        "is_dir": is_dir,
        "note": note or "",
        "timestamp": datetime.now().isoformat()
    }
    metadata_json = json.dumps(metadata).encode("utf-8")
    
    aesgcm = AESGCM(key)
    
    # Encrypt Metadata (v4+)
    metadata_nonce = nonce_prefix + b"\xFF\xFF\xFF\xFF"
    encrypted_metadata = aesgcm.encrypt(metadata_nonce, metadata_json, None)
    
    # Determine output name
    if in_place:
        # Use a temporary file in the same directory for atomic replace
        fd, out_name = tempfile.mkstemp(dir=os.path.dirname(original_path), suffix=".tmp")
        os.close(fd)
    elif hide_image:
        base, ext = os.path.splitext(hide_image)
        out_name = f"{base}_vault{ext}"
    else:
        out_name = (original_path if is_dir else filepath) + ".enc"

    # Set flags
    flags = FLAG_NONE
    if self_destruct:
        flags |= FLAG_SELF_DESTRUCT

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
        
        mode = "wb"
        if hide_image:
            shutil.copy2(hide_image, out_name)
            mode = "ab"

        with open(out_name, mode) as out_f:
            out_f.write(MAGIC_BYTES)
            out_f.write(struct.pack("B", HEADER_VERSION))
            out_f.write(struct.pack("B", flags))
            out_f.write(salt)
            out_f.write(nonce_prefix)
            
            # Write Metadata (v4+)
            out_f.write(struct.pack(">H", len(encrypted_metadata)))
            out_f.write(encrypted_metadata)
            
            # Legacy folder name (empty in v4)
            out_f.write(struct.pack(">H", 0))
            
            with open(filepath, "rb") as in_f:
                while True:
                    chunk = in_f.read(CHUNK_SIZE)
                    if not chunk: break
                    chunk_nonce = nonce_prefix + struct.pack(">I", counter)
                    encrypted_chunk = aesgcm.encrypt(chunk_nonce, chunk, None)
                    out_f.write(encrypted_chunk)
                    counter += 1
                    progress.update(task, advance=len(chunk))

    if in_place:
        # Securely delete original then replace
        if not keep_original:
            secure_delete(original_path)
        os.replace(out_name, original_path)
        out_name = original_path
        msg = f"File encrypted in-place: [cyan]{out_name}[/cyan]"
    else:
        msg = f"File encrypted: [cyan]{out_name}[/cyan]"
        if hide_image:
            msg = f"Vault hidden inside image: [cyan]{out_name}[/cyan]"

    console.print(Panel(f"[bold green]Success![/bold green] 🔐\n{msg}", border_style="green"))

    if temp_zip:
        os.remove(temp_zip)
        shutil.rmtree(os.path.dirname(temp_zip), ignore_errors=True)

    if not keep_original and not in_place:
        console.log("[yellow]Wiping original file(s)...[/yellow]")
        if is_dir: shutil.rmtree(original_path)
        else: secure_delete(original_path)


def decrypt_file(filepath: str, keep_encrypted: bool = False, in_place: bool = False) -> None:
    """Decrypt an encrypted file or directory."""
    if not os.path.exists(filepath):
        console.print(f"[bold red]Error:[/bold red] '{filepath}' does not exist")
        return

    try:
        password = get_password(confirm=False)
    except ValueError as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        return

    temp_out = None
    out_file = None
    is_dir = False
    folder_name = ""
    self_destruct = False
    version = 0
    metadata = {}

    try:
        with open(filepath, "rb") as f:
            content = f.read()
            magic_pos = content.find(MAGIC_BYTES)
            if magic_pos == -1:
                console.print("[bold red]Error:[/bold red] No CryptLock vault found")
                return
            
            f.seek(magic_pos + 4)
            version = struct.unpack("B", f.read(1))[0]
            if version > HEADER_VERSION:
                console.print(f"[bold red]Error:[/bold red] Unsupported version v{version}")
                return

            flags = FLAG_NONE
            if version >= 3:
                flags = struct.unpack("B", f.read(1))[0]

            salt = f.read(SALT_SIZE)
            with console.status("[bold green]Deriving secure key...[/bold green]"):
                key = derive_key(password, salt, version=version)

            nonce_prefix = f.read(8)
            
            if version >= 4:
                meta_len = struct.unpack(">H", f.read(2))[0]
                encrypted_meta = f.read(meta_len)
                aesgcm = AESGCM(key)
                meta_nonce = nonce_prefix + b"\xFF\xFF\xFF\xFF"
                try:
                    metadata_json = aesgcm.decrypt(meta_nonce, encrypted_meta, None)
                    metadata = json.loads(metadata_json.decode("utf-8"))
                except Exception:
                    console.print("[bold red]Error:[/bold red] Wrong password or metadata corrupted")
                    return

            # Legacy folder name
            folder_name_len = struct.unpack(">H", f.read(2))[0]
            legacy_folder_name = f.read(folder_name_len).decode("utf-8") if folder_name_len > 0 else ""
            
            folder_name = metadata.get("filename") if version >= 4 else legacy_folder_name
            is_dir = metadata.get("is_dir", False) if version >= 4 else bool(legacy_folder_name)

            # Determine output name
            if in_place:
                out_file = folder_name or os.path.basename(filepath).replace(".enc", "")
            else:
                base_name = os.path.basename(filepath)
                if "_vault" in base_name:
                    out_file = base_name.replace("_vault", "")
                elif base_name.endswith(".enc"):
                    out_file = base_name[:-4]
                else:
                    out_file = folder_name or (base_name + "_decrypted")

            # Handle collision between out_file and vault itself
            if os.path.abspath(out_file) == os.path.abspath(filepath):
                temp_out_fd, temp_out = tempfile.mkstemp(dir=os.path.dirname(filepath), suffix=".tmp")
                os.close(temp_out_fd)
            else:
                temp_out = out_file + ".tmp"

            self_destruct = bool(flags & FLAG_SELF_DESTRUCT)
            if self_destruct:
                keep_encrypted = False

            if version == 1:
                f.seek(magic_pos + 5)
                salt = f.read(SALT_SIZE)
                iv = f.read(16)
                signature = f.read(32)
                f.read(struct.unpack(">H", f.read(2))[0])
                
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
                aesgcm = AESGCM(key)
                counter = 0
                GCM_CHUNK_SIZE = CHUNK_SIZE + 16
                current_pos = f.tell()
                f.seek(0, os.SEEK_END)
                data_size = f.tell() - current_pos
                f.seek(current_pos)
                with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), DownloadColumn(), TransferSpeedColumn(), TimeRemainingColumn(), console=console) as progress:
                    task = progress.add_task(f"[cyan]Decrypting (v{version})...", total=data_size)
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
                                out_f.close()
                                os.remove(temp_out)
                                return

        # --- OUTSIDE OF 'with open(filepath)' ---
        # Now it's safe to replace the file on Windows
        os.replace(temp_out, out_file)
        
        if is_dir:
            console.log(f"[cyan]Extracting directory: {out_file}[/cyan]")
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
        
        if version >= 4 and metadata.get("note"):
            console.print(f"[bold blue]Note:[/bold blue] {metadata['note']}")

        if self_destruct:
            console.log("[bold red]Self-destruct active: vault file deleted.[/bold red]")

    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        if temp_out and os.path.exists(temp_out):
            os.remove(temp_out)
        return

    if not keep_encrypted:
        try:
            # ONLY delete the vault if it wasn't already overwritten by the output
            if os.path.exists(filepath) and os.path.abspath(filepath) != os.path.abspath(out_file):
                os.remove(filepath)
                console.log("[yellow]Vault file deleted[/yellow]")
        except Exception:
            pass


def show_info(filepath: str) -> None:
    """Show encrypted metadata info."""
    if not os.path.exists(filepath):
        console.print(f"[bold red]Error:[/bold red] '{filepath}' does not exist")
        return

    password = get_password(confirm=False)
    try:
        with open(filepath, "rb") as f:
            content = f.read()
            magic_pos = content.find(MAGIC_BYTES)
            if magic_pos == -1:
                console.print("[bold red]Error:[/bold red] No CryptLock vault found")
                return
            
            f.seek(magic_pos + 4)
            version = struct.unpack("B", f.read(1))[0]
            if version < 4:
                console.print(f"[yellow]Info:[/yellow] File version v{version} does not support encrypted metadata.")
                return

            flags = struct.unpack("B", f.read(1))[0]
            salt = f.read(SALT_SIZE)
            with console.status("[bold green]Deriving secure key...[/bold green]"):
                key = derive_key(password, salt, version=version)

            nonce_prefix = f.read(8)
            meta_len = struct.unpack(">H", f.read(2))[0]
            encrypted_meta = f.read(meta_len)
            
            aesgcm = AESGCM(key)
            meta_nonce = nonce_prefix + b"\xFF\xFF\xFF\xFF"
            metadata_json = aesgcm.decrypt(meta_nonce, encrypted_meta, None)
            metadata = json.loads(metadata_json.decode("utf-8"))

            table = Table(title="Vault Information", show_header=False, box=None)
            table.add_row("Original Name:", f"[cyan]{metadata['filename']}[/cyan]")
            table.add_row("Type:", "Directory" if metadata["is_dir"] else "File")
            table.add_row("Created:", metadata["timestamp"])
            table.add_row("Note:", f"[yellow]{metadata['note'] or 'N/A'}[/yellow]")
            table.add_row("Flags:", "Self-Destruct" if flags & FLAG_SELF_DESTRUCT else "None")
            table.add_row("Version:", f"v{version}")
            
            console.print(Panel(table, title="🔐 CryptLock Vault Info", border_style="blue"))
    except Exception:
        console.print("[bold red]Error:[/bold red] Wrong password or file corrupted")


def main() -> None:
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        description="CryptLock - Secure file and directory encryption CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  cryptlock encrypt secret.txt --note "My secret note"
  cryptlock encrypt sensitive_dir --hide landscape.jpg
  cryptlock decrypt landscape_vault.jpg --in-place
        """,
    )
    subparsers = parser.add_subparsers(dest="command")
    
    # Encrypt
    enc_parser = subparsers.add_parser("encrypt", help="Encrypt a file or directory")
    enc_parser.add_argument("file", help="File or directory to encrypt")
    enc_parser.add_argument("--keep", "-k", action="store_true", help="Keep original after encryption (default: delete)")
    enc_parser.add_argument("--self-destruct", "-s", action="store_true", help="Delete vault after decryption")
    enc_parser.add_argument("--hide", "-H", metavar="IMAGE", help="Hide vault inside an image")
    enc_parser.add_argument("--note", "-n", help="Add an encrypted note to the vault")
    enc_parser.add_argument("--in-place", "-i", action="store_true", help="Encrypt file in-place (danger: replaces original)")
    
    # Decrypt
    dec_parser = subparsers.add_parser("decrypt", help="Decrypt an encrypted file")
    dec_parser.add_argument("file", help="Encrypted file to decrypt")
    dec_parser.add_argument("--keep", "-k", action="store_true", help="Keep the encrypted vault after decryption")
    dec_parser.add_argument("--in-place", "-i", action="store_true", help="Decrypt file in-place (danger: replaces original)")
    
    # Info
    info_parser = subparsers.add_parser("info", help="Show encrypted metadata info")
    info_parser.add_argument("file", help="Encrypted file to inspect")

    parser.add_argument("--version", "-v", action="version", version="CryptLock 3.0.0")

    args = parser.parse_args()
    if args.command == "encrypt":
        encrypt_file(args.file, keep_original=args.keep, self_destruct=args.self_destruct, hide_image=args.hide, note=args.note, in_place=args.in_place)
    elif args.command == "decrypt":
        decrypt_file(args.file, keep_encrypted=args.keep, in_place=args.in_place)
    elif args.command == "info":
        show_info(args.file)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
