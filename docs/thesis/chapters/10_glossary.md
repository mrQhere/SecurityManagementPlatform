# Glossary of Terms

**AES-256**
Advanced Encryption Standard. A symmetric block cipher used by the U.S. government to protect classified information. SMP uses the 256-bit key length variant within SQLCipher.

**CISA KEV**
Cybersecurity and Infrastructure Security Agency's Known Exploited Vulnerabilities catalog. A definitive list of CVEs actively used in cyber attacks.

**CVE**
Common Vulnerabilities and Exposures. A standardized dictionary of publicly known information security vulnerabilities and exposures.

**CVSS**
Common Vulnerability Scoring System. A free and open industry standard for assessing the severity of computer system security vulnerabilities.

**DAG**
Directed Acyclic Graph. A mathematical graph structure that flows in one direction and contains no cycles. Used in SMP to manage non-linear orchestration dependencies.

**EPSS**
Exploit Prediction Scoring System. A data-driven model for estimating the likelihood (probability) that a software vulnerability will be exploited in the wild.

**Fernet**
A symmetric encryption specification utilizing AES-128 in CBC mode, PKCS7 padding, and HMAC-SHA256 for authentication. Used in SMP for encrypting raw tool output blobs on disk.

**Kahn's Algorithm**
An algorithm used to find a topological ordering of a directed acyclic graph. SMP uses this to compute execution order based on in-degree dependencies.

**Local-First**
A software architecture paradigm emphasizing that the primary copy of data should reside on the local device, rather than on a remote cloud server, ensuring maximum privacy and sovereignty.

**PBKDF2**
Password-Based Key Derivation Function 2. A cryptographic algorithm that derives a strong, fixed-length key from a variable-length password to prevent brute-force dictionary attacks.

**PySide6**
The official Python bindings for the Qt framework, providing access to native C++ GUI components.

**SQLCipher**
An open-source extension to SQLite that provides transparent 256-bit AES encryption of database files.

**TF-IDF**
Term Frequency-Inverse Document Frequency. A numerical statistic intended to reflect how important a word is to a document in a collection or corpus. Used by the Neural Brain for semantic clustering.

**VAPT**
Vulnerability Assessment and Penetration Testing. The comprehensive process of identifying, analyzing, and exploiting vulnerabilities in an IT infrastructure.
