# 5. Cryptography and Data Sovereignty

The foundational premise of the Security Management Platform (SMP) is the preservation of absolute data sovereignty. In a Vulnerability Assessment and Penetration Testing (VAPT) context, the orchestration engine inherently centralizes highly classified topological intelligence, undiscovered zero-day exploits, and potentially plaintext credentials extracted from memory dumps or source code repositories. 

Exfiltrating this intelligence to a cloud-based SIEM for processing violates the zero-trust models mandated by federal and defense regulatory bodies. However, retaining this data locally on an analyst's workstation shifts the threat model from network interception to physical endpoint compromise. To mitigate this, SMP implements a dual-layered, military-grade cryptographic architecture to secure all data at rest.

## 5.1 Relational Data Security (SQLCipher and AES-256)

All structured, relational intelligence—such as target hostnames, scanner metadata, and the mathematical vectors computed by the Neural Brain—is persisted within a local SQLite database (`security.db`). Because standard SQLite persists data in plaintext, SMP integrates SQLCipher, a C-based extension that provides transparent, page-level 256-bit Advanced Encryption Standard (AES) encryption in Cipher Block Chaining (CBC) mode.

### 5.1.1 Cryptographic Key Derivation (PBKDF2)
AES-256 requires a 256-bit (32-byte) symmetric cryptographic key. Because human operators cannot memorize 256-bit keys, the system must derive the key from a human-readable master password. 

To protect the derived key against offline dictionary attacks, brute-forcing, and rainbow tables, SMP utilizes Password-Based Key Derivation Function 2 (PBKDF2).

1. **Salting**: The system generates a cryptographically secure, pseudo-random 32-byte salt using the host operating system's entropy pool (`os.urandom(32)`).
2. **Pseudorandom Function (PRF)**: SMP utilizes HMAC-SHA256 as the underlying hashing algorithm.
3. **Iteration Count**: As of V9.4.0, the platform enforces a minimum of 600,000 iterations, strictly adhering to the 2024 recommendations set forth by the National Institute of Standards and Technology (NIST).

The derivation function is defined as:
$$ \text{DK} = \text{PBKDF2}(\text{PRF}, \text{Password}, \text{Salt}, 600000, 32) $$

The resulting 32-byte Derived Key (DK) is converted to a hexadecimal format and passed to SQLCipher via the `PRAGMA key` directive. This key is never stored on disk. If the application is terminated, the memory is released, and the database becomes cryptographically inaccessible.

## 5.2 Unstructured Data Security (Fernet)

While SQLCipher is highly optimized for structured SQL tables, specific security binaries (such as `nuclei` and `ffuf`) emit massive volumes of unstructured JSON or raw text output. Persisting these massive blobs within SQL tables induces severe page fragmentation and drastically reduces database query performance.

Consequently, SMP stores these raw blobs as flat files within the localized file system (`reports/evidence/`). To secure these files, SMP utilizes the `Fernet` specification.

### 5.2.1 The Fernet Implementation
Fernet is a symmetric encryption protocol designed specifically for ensuring that messages (or files) cannot be read or tampered with without the requisite key. It is composed of three primitives:
1. **Confidentiality**: AES in CBC mode with a 128-bit key.
2. **Padding**: PKCS7 to align variable-length data to the AES block size.
3. **Integrity (Authentication)**: HMAC-SHA256, calculated over the ciphertext, to ensure the file has not been maliciously modified on disk.

### 5.2.2 The Key Management Hierarchy
To prevent the user from managing two separate passwords, SMP implements a Master Key architectural hierarchy. 

Upon initial platform configuration, the system generates a cryptographically random 32-byte Fernet key. This Fernet key is subsequently stored *inside* a restricted table within the AES-256 encrypted `security.db` SQLCipher database. 

During normal operations:
1. The user provides the Master Password.
2. PBKDF2 derives the AES-256 key and unlocks `security.db`.
3. The orchestration engine retrieves the Fernet key from the unlocked database.
4. The orchestration engine utilizes the Fernet key to decrypt the massive blob files dynamically in memory during reporting phases.

This architecture ensures a unified cryptographic perimeter. If the host machine is compromised while the platform is offline, the attacker is presented with an impenetrable SQLCipher database and mathematically randomized flat files, ensuring absolute data sovereignty.
