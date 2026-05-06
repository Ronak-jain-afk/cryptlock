# CryptLock 🔐 v2.0

Secure file & directory encryption CLI using **AES-256-GCM** with **Argon2id** key derivation.

## Features

- **AES-256-GCM** - Authenticated encryption providing both confidentiality and integrity.
- **Argon2id** - State-of-the-art memory-hard key derivation (KDF).
- **True Streaming** - Process multi-terabyte files with minimal RAM usage.
- **Safe Decryption** - Integrity verification before final file placement.
- **Rich UI** - Modern CLI interface with beautiful progress bars and status panels.
- **Directory Support** - Automatically zips and encrypts entire folders.
- **Backward Compatible** - Can still decrypt v1 files (AES-CFB + PBKDF2).

## Installation

To install CryptLock locally from the source:

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Ronak-jain-afk/cryptlock.git
   cd cryptlock
   ```

2. **Install dependencies and the package:**
   ```bash
   pip install .
   ```

## Usage

### Encrypt a file
```bash
cryptlock encrypt myfile.txt
```

### Encrypt and wipe original
```bash
cryptlock encrypt myfile.txt --wipe
```

### Encrypt a directory
```bash
cryptlock encrypt myfolder --wipe
```

### Decrypt a file
```bash
cryptlock decrypt myfile.txt.enc
```

### Keep encrypted file after decryption
```bash
cryptlock decrypt myfile.txt.enc --keep
```

## Security Notes

⚠️ **Important Considerations:**

1. **Secure deletion limitations**: The `--wipe` flag attempts to overwrite files, but this is NOT cryptographically secure on SSDs, Copy-on-write (btrfs, ZFS), or journaling filesystems.
2. **Password strength**: While Argon2id is robust against brute-force, always use a strong, unique password.
3. **Backups**: Always keep a backup of critical data before encryption.

## License

MIT License

## Disclaimer

This tool is provided for educational and legitimate security purposes only. The authors are not responsible for any misuse or data loss.
