# CryptLock 🔐

Secure file & directory encryption CLI using AES-256-CFB with PBKDF2 key derivation.

## Installation

```bash
pip install cryptlock
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

## Features

- **AES-256-CFB encryption** - Industry-standard symmetric encryption
- **PBKDF2-SHA256** - 600,000 iterations for key derivation (OWASP 2023 recommendation)
- **HMAC-SHA256** - Integrity verification (Encrypt-then-MAC)
- **Directory support** - Automatically zips and encrypts folders
- **Progress bar** - Visual feedback for large files
- **Cross-platform** - Works on Linux, macOS, and Windows
- **Secure wipe** - Best-effort secure deletion of original files

## Security Notes

⚠️ **Important Security Considerations:**

1. **Secure deletion limitations**: The `--wipe` flag attempts to overwrite files, but this is NOT cryptographically secure on:
   - SSDs (due to wear leveling)
   - Copy-on-write filesystems (btrfs, ZFS)
   - Journaling filesystems
   
   For true secure deletion, use full-disk encryption.

2. **Password strength**: Use strong, unique passwords. The tool uses 600,000 PBKDF2 iterations, but weak passwords can still be brute-forced.

3. **Backup your data**: Always maintain backups before encrypting important files.

## Requirements

- Python 3.8+
- cryptography
- tqdm

## License

MIT License

## Disclaimer

This tool is provided for educational and legitimate security purposes only. The authors are not responsible for any misuse or data loss.
