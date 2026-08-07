# Chapter 6: Cryptography & Data Sovereignty

The core philosophy of the Security Management Platform is absolute data sovereignty. A vulnerability scanner inherently collects the most sensitive data an organization possesses: network topologies, unpatched CVEs, zero-day vulnerabilities, exposed internal APIs, and occasionally, plaintext credentials embedded in source code. 

Transmitting this data to a cloud provider—regardless of their security certifications—introduces unacceptable risk for defense contractors, financial institutions, and government entities. Consequently, SMP is designed to operate entirely air-gapped, retaining all data locally. 

However, local data storage introduces the risk of physical endpoint compromise. If a penetration tester's laptop is stolen, the raw SQLite databases could provide a threat actor with a complete map of the target's weaknesses. This chapter details the multi-layered cryptographic architecture implemented to secure this data at rest.

## 6.1 Database Encryption: SQLCipher (AES-256)

Standard SQLite stores data in plaintext. To mitigate this, SMP integrates `SQLCipher`, an open-source extension to SQLite that provides transparent, page-level 256-bit Advanced Encryption Standard (AES) encryption in Cipher Block Chaining (CBC) mode.

All critical relational data—including scan metadata, target URLs, and the structured vulnerability findings—are stored in `database/security.db`, which is encrypted by SQLCipher.

### 6.1.1 Key Derivation (PBKDF2)
A 256-bit AES key is required to unlock the database, but humans cannot memorize 256-bit cryptographic keys. SMP derives this key from a user-provided master password.

To protect against offline dictionary attacks and rainbow tables, the master password is subjected to Password-Based Key Derivation Function 2 (PBKDF2).

1. **Salting**: SMP generates a cryptographically secure 32-byte random salt.
2. **Hashing Algorithm**: HMAC-SHA256 is used as the underlying pseudorandom function.
3. **Iterations**: As of V9, SMP enforces a minimum of 600,000 iterations (aligning with NIST 2024 guidelines). 

```python
# Conceptual Key Derivation Process
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

salt = os.urandom(32)
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,          # 256-bit key
    salt=salt,
    iterations=600000,
)
master_key = kdf.derive(b"user_provided_password")
```

The resulting 32-byte key is converted to a hexadecimal string and passed to SQLCipher via the `PRAGMA key` directive immediately upon connection. If the incorrect password is provided, SQLCipher simply returns a `file is not a database` error, as it cannot decrypt the header.

## 6.2 Blob Encryption: Fernet

While SQLCipher is exceptionally efficient for structured, relational data, SMP also needs to store massive amounts of unstructured data. Tools like `ffuf` or `nuclei` can generate megabytes of raw JSON or text output per scan. Storing these massive blobs directly inside the SQLite database leads to severe performance degradation and database fragmentation.

Therefore, SMP stores raw scanner outputs as flat files on the filesystem (e.g., in the `reports/evidence/` directory). However, these files must also be encrypted.

For file-based encryption, SMP utilizes the `Fernet` specification from the Python `cryptography` library.

### 6.2.1 The Fernet Implementation
Fernet guarantees that a message encrypted using it cannot be manipulated or read without the key. It utilizes:
- **AES-128 in CBC mode** for confidentiality.
- **PKCS7 padding** for block alignment.
- **HMAC-SHA256** for integrity verification (ensuring the ciphertext hasn't been tampered with).

The 32-byte URL-safe base64-encoded key required by Fernet is securely stored *inside* the encrypted `security.db` SQLCipher database. 

This creates a master-key architecture:
1. The user inputs their Master Password.
2. PBKDF2 derives the AES-256 key to unlock `security.db`.
3. SMP reads the internal `system_secrets` table to retrieve the Fernet key.
4. SMP uses the Fernet key to decrypt the raw flat files on the disk.

This ensures that if the laptop is stolen, both the relational database and the flat files are cryptographically inaccessible.

## 6.3 Separation of Concerns: Plaintext Intelligence

Not all databases in SMP are encrypted. The platform adheres to strict separation of concerns to maximize performance.

The `intelligence/` directory contains `global_intel.db` and various CVE/EPSS caching databases. Because these databases contain only public intelligence data (e.g., the mathematical definition of a CVE or the global centrality scores calculated by the Neural Brain) and contain *zero* client-specific data or PII, they are deliberately left as standard, unencrypted SQLite databases.

This allows the Neural Brain and orchestration engines to perform massive concurrent `SELECT` queries against the intelligence feeds at maximum disk I/O speed, reserving the CPU-intensive AES decryption cycles exclusively for the sensitive pentest data.
