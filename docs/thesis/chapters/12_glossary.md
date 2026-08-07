# 10. Glossary of Terms

**AES-256 (Advanced Encryption Standard)**  
A symmetric block cipher utilized by the U.S. government to protect classified information. SMP uses the 256-bit key length variant within SQLCipher.

**CISA KEV (Known Exploited Vulnerabilities)**  
A definitive catalog maintained by the Cybersecurity and Infrastructure Security Agency listing CVEs actively used in cyber attacks.

**Cosine Similarity**  
A mathematical measure of similarity between two non-zero vectors. SMP uses this within the TF-IDF clustering engine to mathematically group related vulnerabilities.

**CVE (Common Vulnerabilities and Exposures)**  
A standardized dictionary of publicly known information security vulnerabilities and exposures.

**CVSS (Common Vulnerability Scoring System)**  
An open industry standard for assessing the severity of computer system security vulnerabilities.

**DAG (Directed Acyclic Graph)**  
A mathematical graph structure that flows in one direction and contains no cycles. Used in SMP to manage non-linear orchestration dependencies.

**EPSS (Exploit Prediction Scoring System)**  
A data-driven model for estimating the likelihood (probability) that a software vulnerability will be exploited in the wild.

**Fernet**  
A symmetric encryption specification utilizing AES-128 in CBC mode, PKCS7 padding, and HMAC-SHA256 for authentication. Used in SMP for encrypting raw tool output blobs on disk.

**Kahn's Algorithm**  
An algorithm used to find a topological ordering of a directed acyclic graph. SMP uses this to compute execution order based on in-degree dependencies.

**Levenshtein Distance**  
A string metric for measuring the difference between two sequences. SMP uses this to deduplicate findings.

**Local-First**  
A software architecture paradigm emphasizing that the primary copy of data should reside on the local device, rather than on a remote cloud server, ensuring maximum privacy and sovereignty.

**PBKDF2 (Password-Based Key Derivation Function 2)**  
A cryptographic algorithm that derives a strong, fixed-length key from a variable-length password to prevent brute-force dictionary attacks. SMP strictly enforces 600,000 iterations.

**PySide6**  
The official Python bindings for the Qt framework, providing access to native C++ GUI components.

**SQLCipher**  
An open-source extension to SQLite that provides transparent 256-bit AES encryption of database files.

**TF-IDF (Term Frequency-Inverse Document Frequency)**  
A numerical statistic intended to reflect how important a word is to a document in a collection or corpus. Used by the Neural Brain for semantic clustering.

\newpage
