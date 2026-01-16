#!/usr/bin/env python3

import shutil
import tempfile
import zipfile
from tqdm import tqdm
from cryptography.hazmat.primitives import hmac
import argparse
import os
from getpass import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import secrets

backend = default_backend()

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    return kdf.derive(password.encode())

def encrypt_file(filepath,wipe=False):
    original_path = filepath 
    is_dir = os.path.isdir(filepath)
    temp_zip = None
    
    if is_dir:
        print("📁 Zipping directory...")
        temp_zip = zip_directory(filepath)
        filepath = temp_zip

    password = getpass("Enter password: ")
    confirm = getpass("Confirm password: ")

    if password != confirm:
        print("❌ Passwords do not match")
        return

    salt = secrets.token_bytes(16)
    key = derive_key(password, salt)
    iv = secrets.token_bytes(16)

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
    encryptor = cipher.encryptor()

    file_size = os.path.getsize(filepath)

    encrypted_chunks = []

    with open(filepath, "rb") as f:
        for chunk in tqdm(iter(lambda: f.read(4096), b""),
                          total=(file_size // 4096) + 1,
                          desc="Encrypting",
                          unit="blocks"):
            encrypted_chunks.append(encryptor.update(chunk))

    encrypted = b"".join(encrypted_chunks) + encryptor.finalize()


    folder_name = b""

    if is_dir:
        folder_name = os.path.basename(original_path).encode() + b"\n"


    signature = create_hmac(key, folder_name + encrypted)

    out_name = filepath + ".enc"
    with open(out_name, "wb") as f:
        f.write(salt + iv + signature + folder_name + encrypted)



    print("✅ File encrypted:", filepath + ".enc")
    # cleanup temp zip
    if temp_zip:
        os.remove(temp_zip)

    if wipe:
        if is_dir:
            shutil.rmtree(original_path)
        else:
            secure_delete(original_path)

def zip_directory(folder):
    base = tempfile.mktemp()
    zip_path = shutil.make_archive(base, 'zip', folder)
    return zip_path

def unzip_file(zip_path, out_dir):
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(out_dir)


def secure_delete(filepath):
    size = os.path.getsize(filepath)

    with open(filepath, "r+b") as f:
        f.write(secrets.token_bytes(size))

    os.remove(filepath)
def create_hmac(key, data):
    h = hmac.HMAC(key, hashes.SHA256(), backend=backend)
    h.update(data)
    return h.finalize()


def decrypt_file(filepath):
    password = getpass("Enter password: ")

    with open(filepath, "rb") as f:
        raw = f.read()

    salt = raw[:16]
    iv = raw[16:32]
    signature = raw[32:64]
    rest = raw[64:]
    # check if folder metadata exists
    if b"\n" in rest:
        meta, ciphertext = rest.split(b"\n", 1)
        folder_name = meta.decode()

    else:
        ciphertext = rest
        original_path = None


    key = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
    decryptor = cipher.decryptor()

    try:
        expected = create_hmac(
    key,
    (folder_name.encode()+b"\n" if folder_name else b"") + ciphertext
)



        from cryptography.hazmat.primitives.constant_time import bytes_eq
        if not bytes_eq(expected, signature):
            print("❌ Wrong password or file corrupted")
            return

    except Exception:
        print("❌ Wrong password or file corrupted")
        return

    decrypted_chunks = []

    for chunk in tqdm(
        [ciphertext[i:i+4096] for i in range(0, len(ciphertext), 4096)],
        desc="Decrypting",
        unit="blocks"
    ):
        decrypted_chunks.append(decryptor.update(chunk))

    decrypted = b"".join(decrypted_chunks) + decryptor.finalize()

    out_file = os.path.basename(filepath.replace(".enc", ""))

    with open(out_file, "wb") as f:
        f.write(decrypted)

    print("✅ File decrypted:", out_file)

    # If it's a directory zip
    if out_file.endswith(".zip") and folder_name:
        print("📂 Extracting directory...")
        unzip_file(out_file, folder_name)
        os.remove(out_file)

    # delete encrypted file
    os.remove(filepath)
    print("🗑 Encrypted file deleted")


def main():
    parser = argparse.ArgumentParser(description="CryptLock - File encryption tool")

    sub = parser.add_subparsers(dest="command")

    enc = sub.add_parser("encrypt")
    enc.add_argument("file")
    enc.add_argument(
    "--wipe",
    action="store_true",
    help="Delete original file after encryption"
)


    dec = sub.add_parser("decrypt")
    dec.add_argument("file")

    args = parser.parse_args()

    if args.command == "encrypt":
        encrypt_file(args.file,args.wipe)

    elif args.command == "decrypt":
        decrypt_file(args.file)

    else:
        parser.print_help()

if __name__ == "__main__":
    main()
