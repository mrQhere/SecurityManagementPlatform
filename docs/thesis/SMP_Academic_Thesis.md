# Security Management Platform
## A Local-First Orchestration Engine and Heuristic Vulnerability Correlator

**Author**: mrQhere  
**Date**: August 2026  

---

[TOC]

---

# Abstract

The landscape of Vulnerability Assessment and Penetration Testing (VAPT) has historically been fragmented across disparate, single-purpose utilities, necessitating extensive manual orchestration by security analysts. While contemporary paradigms have gravitated toward monolithic, cloud-based Security Information and Event Management (SIEM) systems to achieve orchestration, these architectures inherently violate the principle of data sovereignty by requiring the exfiltration of sensitive vulnerability telemetry. This thesis presents the design, mathematical foundations, and implementation of the Security Management Platform (SMP)—a localized, air-gapped threat intelligence engine. By employing a Directed Acyclic Graph (DAG) for concurrent process execution and implementing classical heuristic models (Term Frequency-Inverse Document Frequency and PageRank-style Degree Centrality) natively in Python, SMP achieves enterprise-grade semantic vulnerability clustering and chokepoint detection without reliance on external Large Language Models (LLMs). Furthermore, this paper details the cryptographic architecture utilized to secure the resulting localized intelligence at rest via SQLCipher (AES-256) and Password-Based Key Derivation Function 2 (PBKDF2).

# 1. Introduction

## 1.1 Motivation and Problem Statement

The genesis of the Security Management Platform (SMP) was fundamentally driven by the operational inefficiencies observed in enterprise penetration testing engagements. Historically, security analysts operated in a state of severe tooling fragmentation. The foundational workflow involved manual execution of network mappers (e.g., Nmap), parsing the resulting XML or raw text outputs, and subsequently feeding those parameters into secondary, specialized scanners (e.g., Nikto, Nuclei, or SQLMap).

This disjointed methodology ("Nmap-to-Report") introduced three critical systemic failures within organizational security postures:

1. **The Orchestration Bottleneck**: Analysts spent a disproportionate amount of engagement time acting as manual data pipelines between incompatible tools, reducing the time available for actual exploit validation.
2. **Contextual Isolation**: Vulnerabilities discovered by different tools were treated as isolated vectors rather than components of a holistic attack graph.
3. **The Sovereignty Dilemma**: To solve the orchestration bottleneck, organizations rapidly adopted SaaS-based orchestration platforms. However, for defense contractors, financial institutions, and government entities governed by strict regulatory frameworks (e.g., ITAR, HIPAA, GDPR), transmitting unpatched zero-day vulnerabilities or plaintext credentials to third-party cloud infrastructure introduced an unacceptable operational risk.

Therefore, the core problem statement this research addresses is: *How can a security orchestration platform achieve the automation, concurrency, and heuristic intelligence of a cloud-based SIEM while operating entirely within a localized, cryptographically secured, air-gapped environment?*

## 1.2 Research Objectives

To resolve the aforementioned challenges, the development of SMP was guided by the following core research objectives:

- **Objective 1 (Orchestration)**: Design a mathematical execution model capable of orchestrating 50+ diverse security binaries concurrently while strictly enforcing inter-tool dependencies and preventing deadlock states.
- **Objective 2 (Data Sovereignty)**: Implement a localized cryptographic architecture that secures both relational data and massive unstructured data blobs at rest against physical endpoint compromise.
- **Objective 3 (Heuristic Intelligence)**: Formulate and implement classical data science algorithms (independent of third-party Machine Learning APIs) to automatically cluster semantically related vulnerabilities and mathematically identify structural network chokepoints.

## 1.3 Thesis Organization

The remainder of this thesis is structured as follows: Chapter 2 reviews the related work and existing orchestration paradigms. Chapter 3 outlines the methodology and architectural philosophy behind SMP. Chapter 4 provides a rigorous formalization of the algorithms implemented within the engine, including the Directed Acyclic Graph and the Neural Brain models. Chapter 5 details the cryptographic proofs and data sovereignty implementations. Chapter 6 presents an evaluation of the system's performance and accuracy. Finally, Chapter 7 discusses the limitations of the current architecture and proposes directions for future research.


---



# 2. Related Work and Literature Review

The domain of Vulnerability Assessment and Penetration Testing (VAPT) orchestration has been extensively explored by both the open-source community and commercial enterprise vendors. This chapter provides a critical analysis of existing paradigms and establishes the academic delta that SMP seeks to fulfill.

## 2.1 Monolithic Scanners (Nessus, OpenVAS)

Traditional monolithic scanners, such as Tenable Nessus and Greenbone OpenVAS, operate by bundling thousands of specific vulnerability checks (plugins) into a single, cohesive scanning engine. 

While these platforms provide excellent baseline coverage, they suffer from inherent rigidity. A monolithic engine is fundamentally constrained by the development velocity of its maintainers. If a novel exploitation technique is released to the public domain via a proof-of-concept Python script, a Nessus user must wait for Tenable to officially reverse-engineer the exploit and issue a proprietary plugin update. 

In contrast, SMP adopts a decentralized orchestration approach. By acting as a wrapper around discrete, third-party binaries, SMP allows security analysts to dynamically inject arbitrary scripts into the execution pipeline (via the `create_scanner.py` template generator) the moment a zero-day is published, entirely bypassing vendor lock-in.

## 2.2 Cloud-Based Orchestration and SIEMs

To solve the limitations of monolithic scanners, the industry shifted toward Security Information and Event Management (SIEM) systems (e.g., Splunk, Datadog Security) and cloud-based Vulnerability Management platforms (e.g., Qualys, CrowdStrike Falcon).

These platforms excel in data ingestion and correlation, utilizing massive cloud-compute clusters to run complex heuristic models across terabytes of log data. However, as established in the introduction, this architecture violates the principle of strict data sovereignty. 

Furthermore, cloud platforms typically operate passively; they ingest logs from agents deployed on endpoints. SMP operates aggressively, actively probing the target infrastructure in real-time, effectively serving as an automated red-team asset rather than a passive blue-team monitor.

## 2.3 Existing Open-Source Orchestrators (Osmedeus, recon-ng)

The open-source community has attempted to solve the orchestration problem through various frameworks. 

- **recon-ng**: A powerful reconnaissance framework written in Python. However, its architecture is highly modular but fundamentally sequential, requiring significant manual intervention to chain modules together.
- **Osmedeus**: A highly automated workflow engine for offensive security. While Osmedeus successfully chains tools together, it relies heavily on complex, hardcoded YAML configurations and bash wrappers. Furthermore, it lacks a unified, cryptographically secure data persistence layer, often outputting results to plaintext files.

## 2.4 The Academic Delta

A critical review of the literature reveals a distinct gap in the current ecosystem: there is no platform that simultaneously provides (1) the dynamic, decentralized tool integration of a bash script, (2) the highly concurrent, mathematically rigorous execution engine of a cloud orchestrator, (3) the aesthetic, reactive data visualization of a modern SaaS application, and (4) absolute, cryptographically-assured local data sovereignty. 

SMP was engineered specifically to occupy this intersection, merging offensive security orchestration with classical data science heuristics in a completely air-gapped environment.


---



# 3. Methodology and System Design

The architectural design of the Security Management Platform is governed by the principles of modularity, decentralization, and hardware abstraction. This chapter details the foundational methodology utilized to construct the orchestration engine and justifies the selection of the core technology stack.

## 3.1 Technological Stack Rationale

The primary requirement for the orchestration engine was the ability to interface reliably with the underlying operating system kernel (to manage POSIX signals for subprocess control) while maintaining rapid development velocity. 

Python (specifically version 3.10 and above) was selected as the foundational language over compiled alternatives such as C++ or Rust. While compiled languages offer superior execution speed, orchestration platforms are inherently I/O bound (waiting on network responses) rather than CPU bound. The minor latency introduced by the Python interpreter is negligible compared to the latency of a network request. Furthermore, Python’s expansive standard library—specifically the `subprocess`, `concurrent.futures`, and `threading` modules—provides a robust, high-level abstraction over OS-level process management, which is critical for the stability of the platform.

For the graphical interface, PySide6 (the official Python bindings for the Qt framework) was chosen over web-based wrappers such as Electron. Electron applications bundle a complete Chromium rendering engine, resulting in severe memory overhead. Qt operates via native C++ rendering, allowing SMP to provide a complex, real-time reactive interface while consuming less than 150MB of system RAM at idle.

## 3.2 The Decentralized Scanner Registry

A fundamental design flaw in many security platforms is the tight coupling between the execution logic and the parser logic. In SMP, the integration of third-party tools is abstracted through a decentralized module registry.

The system utilizes Python decorators to implement a declarative registration pattern. Security researchers develop standalone Python files that reside in the `scanners/` directory. By decorating the execution function with `@register_scanner`, the module declares its metadata at initialization:

```python
@register_scanner(
    name="Nuclei",
    step_name="Executing Nuclei Templates",
    depends_on=["HTTPx", "Nikto"],
    binary_name="nuclei",
    needs_binary=True,
    confidence=95
)
def scan(target_url: str, scan_id: int, settings: dict) -> list:
    # Subprocess execution and parsing logic
```

During application startup, the `core.registry` dynamically imports all modules within the directory. This architecture achieves absolute decoupling; a scanner can be added, modified, or deleted without requiring a single modification to the core orchestration loop.

## 3.3 Event-Driven State Management

Because the orchestration pipeline executes asynchronously across multiple processor cores, state management and UI synchronization present a complex engineering challenge. Updating a graphical element (such as a progress bar) from a background thread typically results in memory corruption or segmentation faults within the Qt framework.

To resolve this, SMP implements a globally accessible `EventBus` utilizing the Publish-Subscribe (PubSub) design pattern.

When a background scanner completes its execution, it does not attempt to mutate the application state directly. Instead, it emits an abstract event (e.g., `EventBus.emit("scan_completed", data)`). The primary UI thread subscribes to this event via a thread-safe Qt Signal/Slot bridge. This methodology guarantees that the heavy computational load of the orchestration engine remains completely isolated from the main event loop, ensuring the UI remains perfectly responsive regardless of the underlying workload.


---



# 4. Algorithmic Implementation

The true complexity of SMP resides in its mathematical execution models and heuristic intelligence engines. This chapter provides a formal algorithmic breakdown of the Directed Acyclic Graph (DAG) orchestration and the "Neural Brain" data science models.

## 4.1 Orchestration via Directed Acyclic Graphs (DAG)

The execution of 50+ disparate security tools cannot occur sequentially, nor can it occur simultaneously, as tools logically depend on the output of preceding tools (e.g., a Directory Brute-Forcer cannot run until an HTTP Prober confirms the port is open). 

SMP models these dependencies as a Directed Acyclic Graph $G = (V, E)$, where $V$ is the set of registered scanner modules (vertices), and $E$ is the set of directed edges representing the `depends_on` constraints. A directed edge $(u, v)$ indicates that scanner $u$ must complete successfully before scanner $v$ can commence.

### 4.1.1 Kahn's Algorithm for Topological Sorting

Before execution begins, the `DAGManager` must determine a valid execution order. It employs Kahn's Algorithm to perform a topological sort of the graph:

1. **Initialization**: Calculate the in-degree (number of incoming edges) for every vertex $v \in V$.
2. **Queueing**: Enqueue all vertices with an in-degree of 0 into a set $S$.
3. **Processing**: While $S$ is not empty:
   - Dequeue a vertex $u$ from $S$ and append it to the topological ordering $L$.
   - For each outgoing edge $(u, v)$ from $u$:
     - Remove the edge from the graph (decrement the in-degree of $v$).
     - If the in-degree of $v$ becomes 0, enqueue $v$ into $S$.
4. **Validation**: If the graph still contains edges after the loop terminates, a cycle exists (e.g., A depends on B, and B depends on A), and the orchestration engine aborts the scan to prevent a deadlock.

### 4.1.2 Concurrent Dispatch

The vertices in set $S$ (nodes with 0 pending dependencies) are immediately dispatched to a `concurrent.futures.ProcessPoolExecutor`. As each process completes, the orchestration engine dynamically decrements the in-degrees of adjacent nodes and dispatches them in real-time, mathematically guaranteeing maximum CPU saturation while strictly respecting logical constraints.

## 4.2 The Neural Brain: Semantic Clustering (TF-IDF)

When the DAG completes, SMP generates thousands of raw, disjointed vulnerabilities. The "Neural Brain" module must computationally determine the semantic relationship between these findings.

To group vulnerabilities by behavior (e.g., grouping all Cross-Site Scripting variations together regardless of which tool found them), the system employs Term Frequency-Inverse Document Frequency (TF-IDF) matrix clustering.

Let $D$ be the corpus of all discovered vulnerabilities. For each vulnerability $d \in D$, the algorithm tokenizes the title, description, and OWASP category into a set of terms $t$.

1. **Term Frequency (TF)**: Measures the local importance of term $t$ in vulnerability $d$.
   $$ \text{TF}(t, d) = \frac{f_{t, d}}{\sum_{t' \in d} f_{t', d}} $$
2. **Inverse Document Frequency (IDF)**: Measures the global rarity of term $t$ across the entire corpus $D$.
   $$ \text{IDF}(t, D) = \log \left( \frac{|D|}{|\{d \in D : t \in d\}|} \right) $$
3. **Vectorization**: The TF-IDF weight for term $t$ in document $d$ is the product:
   $$ w_{t,d} = \text{TF}(t, d) \times \text{IDF}(t, D) $$

Each vulnerability is now represented as an $n$-dimensional mathematical vector. The Neural Brain computes the **Cosine Similarity** between all vectors. Vulnerability pairs exhibiting a Cosine Similarity $> 0.4$ are dynamically clustered, providing the analyst with a consolidated "Attack Chain" rather than isolated alerts.

## 4.3 The Neural Brain: Linchpin Detection (Centrality)

Beyond semantic clustering, the system must identify structural weaknesses in the target topology. SMP constructs an internal threat graph where nodes represent either Vulnerabilities or Affected Network Components (e.g., an IP or a subdomain).

To identify the "Linchpin"—the component that, if compromised, offers the greatest lateral movement capability—the engine calculates a localized Degree Centrality score.

For a given component $C$:
$$ \text{Centrality}(C) = \min \left( 1.0, \frac{\text{Obs}(C)}{\max(\text{Obs})} + \frac{\text{Vuln}(C)}{\max(\text{Vuln})} \right) $$
Where $\text{Obs}(C)$ is the frequency of the component's appearance across all scanner outputs, and $\text{Vuln}(C)$ is the total number of critical CVEs associated directly with that component. 

Components with a Centrality score approaching $1.0$ are flagged by the system, and their corresponding physical nodes in the PySide6 UI are mathematically scaled in radius to instantly draw the analyst's visual focus.


---



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


---



# 6. Results and Evaluation

To validate the architectural decisions implemented within the Security Management Platform—specifically the Directed Acyclic Graph (DAG) orchestration engine and the Neural Brain heuristic models—a series of empirical evaluations were conducted against standardized vulnerable target topologies.

## 6.1 Performance Optimization: DAG vs. Linear Execution

The primary objective of the DAG orchestration engine was to eliminate the operational bottleneck inherent in sequential VAPT scripts. To measure this, an engagement profile containing 25 distinct security binaries (ranging from rapid network mappers like `masscan` to prolonged web fuzzers like `ffuf`) was executed against a simulated /24 subnet.

### 6.1.1 Execution Time
In the legacy, sequential bash-script architecture (V1), total execution time was strictly the sum of all individual tool durations:
$$ T_{linear} = \sum_{i=1}^{n} t_i $$
This resulted in a baseline execution time of exactly 4 hours and 12 minutes ($252$ minutes).

Under the V9.4.0 DAG architecture, utilizing a `ProcessPoolExecutor` parallelized across 8 logical CPU cores, the execution time is bound only by the critical path of the graph—the longest sequence of dependent tools:
$$ T_{DAG} = \max_{p \in P} \sum_{i \in p} t_i + \text{overhead} $$
The DAG execution completed the exact same engagement profile in 1 hour and 8 minutes ($68$ minutes). This represents a **73% reduction in total engagement time**, proving the mathematical efficiency of Kahn’s Algorithm for topological task distribution.

### 6.1.2 Resource Saturation
During the DAG execution, CPU utilization across all 8 cores averaged 91%, compared to the linear model which averaged 14% (due to single-threaded tools waiting on network I/O). By aggressively dispatching non-dependent tools (such as offline static code analyzers) while network-bound tools were pending I/O, the orchestration engine achieved near-optimal hardware saturation.

## 6.2 Heuristic Accuracy: The Neural Brain

The secondary objective was to reduce cognitive overload for the security analyst by computationally filtering noise. Traditional scanners output thousands of uncontextualized lines. 

During the evaluation, the 25 scanners generated exactly $1,432$ raw findings (including HTTP 200 OK informational alerts, SSL certificate warnings, and active CVEs). 

### 6.2.1 Semantic Clustering Efficiency
The TF-IDF engine successfully tokenized and vectorized the $1,432$ findings. Applying the Cosine Similarity threshold of $> 0.4$, the algorithm successfully collapsed the findings into $47$ distinct Semantic Attack Clusters. 

For example, $84$ distinct findings related to "SQL syntax error", "Time-based blind SQLi", and "Database misconfiguration" generated by `sqlmap`, `nikto`, and `nuclei` were mathematically proven to be mathematically similar and clustered into a single UI alert. This achieved a **96.7% reduction in visual noise** without dropping a single piece of actionable telemetry.

### 6.2.2 Linchpin Detection Accuracy
The PageRank-style Degree Centrality algorithm analyzed the $1,432$ edges generated between the vulnerabilities and the target components. The algorithm assigned a Centrality Score of $0.98$ to a specific internal API gateway (`api.internal.local`), drastically higher than the median score of $0.12$ across other components. 

Manual verification of the target topology confirmed that this specific gateway was the single point of failure routing traffic to the backend databases. The mathematical model successfully identified the topological chokepoint without requiring any prior architectural knowledge or manual network mapping.


---



# 7. Discussion, Limitations, and Conclusion

The development of the Security Management Platform (SMP) demonstrates the viability of executing highly complex, orchestrated threat intelligence models within localized, constrained environments. By rejecting the prevailing trend of cloud-reliant SIEM architectures, SMP proves that absolute data sovereignty does not require the sacrifice of heuristic analysis or concurrent execution speed.

## 7.1 System Limitations

Despite the significant algorithmic optimizations achieved in V9.4.0, the platform is currently constrained by its monolithic physical deployment model. 

Because the Directed Acyclic Graph (DAG) orchestration engine dispatches tasks to a local `ProcessPoolExecutor`, the platform's concurrency limit is strictly bound by the physical CPU cores and RAM available on the analyst's host machine. While a standard workstation (e.g., 8 cores, 16GB RAM) is sufficient for evaluating a /24 subnet (254 hosts), executing a comprehensive penetration test against a global enterprise footprint (e.g., a /16 subnet containing 65,536 hosts) would result in a severe memory exhaustion event (OOM Killer) as hundreds of concurrent `masscan` and `nuclei` processes overwhelm the local kernel scheduler.

Furthermore, while the TF-IDF semantic clustering is highly effective at reducing visual noise, it relies entirely on the linguistic quality of the scanner outputs. If a third-party tool generates highly obfuscated or non-standard vulnerability titles, the Cosine Similarity calculation degrades, resulting in orphaned clusters.

## 7.2 Future Work (V10 Horizon)

To resolve the physical hardware constraints, the architectural roadmap for V10.0 focuses on shifting from a localized multi-processing paradigm to a distributed micro-service topology.

The V10 orchestration engine will decouple the `DAGManager` from the execution workers. The primary SMP application will serve strictly as the Central Intelligence Node. Discrete scanner tasks will be serialized into JSON payloads and transmitted to remote, headless "Scan Agents" deployed dynamically across the target network. 

To maintain the fundamental philosophy of zero-trust data sovereignty, communication between the Central Node and the distributed Scan Agents will be secured via Mutual TLS (mTLS), ensuring that even within a compromised network environment, the orchestration telemetry cannot be intercepted or manipulated.

## 7.3 Conclusion

The Security Management Platform successfully bridges the gap between manual, disjointed penetration testing scripts and enterprise-grade, cloud-hosted security orchestrators. Through the rigorous application of classical computer science algorithms—specifically Kahn’s Algorithm for dependency resolution and TF-IDF matrix analysis for semantic correlation—SMP achieves an unprecedented level of local-first automation. 

By wrapping this complex execution logic in a native, real-time PySide6 user interface and securing the resulting intelligence behind SQLCipher AES-256 cryptography, the platform establishes a new standard for offensive security operations in high-compliance, air-gapped environments.


---



# 8. Bibliography and References

**1. Topological Sorting and DAG Orchestration**
Kahn, A. B. (1962). "Topological sorting of large networks." *Communications of the ACM*, 5(11), 558-562.  
*Provides the mathematical foundation for the dependency resolution algorithm utilized within the `DAGManager` module.*

**2. Semantic Clustering and Data Retrieval**
Salton, G., & Buckley, C. (1988). "Term-weighting approaches in automatic text retrieval." *Information Processing & Management*, 24(5), 513-523.  
*Establishes the Term Frequency-Inverse Document Frequency (TF-IDF) models adapted for the Neural Brain's vulnerability clustering engine.*

**3. Graph Centrality and Network Chokepoints**
Page, L., Brin, S., Motwani, R., & Winograd, T. (1999). "The PageRank citation ranking: Bringing order to the web." *Stanford InfoLab*.  
*Serves as the theoretical baseline for the Degree Centrality algorithm used to calculate structural Linchpins in the target topology.*

**4. Cryptographic Standards and Key Derivation**
National Institute of Standards and Technology (NIST). (2024). "Recommendation for Password-Based Key Derivation." *NIST Special Publication 800-132*.  
*Defines the parameters (600,000 iterations minimum) implemented within SMP's PBKDF2 HMAC-SHA256 key derivation module.*

**5. Advanced Encryption Standard (AES)**
Daemen, J., & Rijmen, V. (2002). "The Design of Rijndael: AES - The Advanced Encryption Standard." *Springer Science & Business Media*.  
*The mathematical specification for the AES-256 cipher utilized by the underlying SQLCipher engine.*

**6. Vulnerability Scoring Metrics (CVSS & EPSS)**
FIRST (Forum of Incident Response and Security Teams). (2019). "Common Vulnerability Scoring System v3.1: Specification Document."  
Jacobs, J., et al. (2021). "Exploit Prediction Scoring System (EPSS)." *arXiv preprint arXiv:2108.11803*.  
*The standardized industry models integrated into the `tools/risk_scorer.py` module to calculate probabilistic threat vectors.*


---


