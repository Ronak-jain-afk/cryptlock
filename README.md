# CryptLock 🔐 v3.0

Secure file & directory encryption CLI using **AES-256-GCM** with **Argon2id** key derivation.

## Features

- **AES-256-GCM** - Authenticated encryption providing both confidentiality and integrity.
- **Argon2id** - State-of-the-art memory-hard key derivation (KDF).
- **Default Deletion** - Original files are securely wiped by default after encryption (safety first!).
- **Encrypted Metadata (v4)** - Store original filenames, timestamps, and custom notes inside the vault.
- **In-place Encryption** - Replace original files with encrypted versions directly.
- **True Streaming** - Process multi-terabyte files with minimal RAM usage.
- **Hidden Vaults** - Hide your data inside standard image files (steganography).
- **Self-Destruct** - Vaults that automatically delete themselves after one successful decryption.
- **Rich UI** - Modern CLI interface with progress bars and status panels.

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

### Encrypt a file (Deletes original by default)
```bash
cryptlock encrypt secret.txt
```

### Encrypt and Keep original
```bash
cryptlock encrypt secret.txt --keep
```

### Encrypt with a Note
```bash
cryptlock encrypt secret.txt --note "Finance records 2024"
```

### In-place Encryption/Decryption
```bash
cryptlock encrypt secret.txt --in-place
cryptlock decrypt secret.txt --in-place
```

### View Vault Info (without decrypting)
```bash
cryptlock info secret.txt.enc
```

### Hidden Vault (Image)
```bash
cryptlock encrypt secret.txt --hide my_photo.jpg
```

### Self-Destructing Vault
```bash
cryptlock encrypt secret.txt --self-destruct
```

## Security Notes

⚠️ **Important Considerations:**

1. **Secure deletion limitations**: CryptLock attempts to overwrite files before deletion, but this is NOT cryptographically secure on SSDs or journaling filesystems.
2. **Password strength**: While Argon2id is robust, always use a strong password.
3. **Backups**: Always keep a backup of critical data before encryption.

## License

MIT License
