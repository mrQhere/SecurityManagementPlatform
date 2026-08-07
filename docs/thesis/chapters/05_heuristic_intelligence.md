# Chapter 5: Heuristic Intelligence & The Neural Brain

The transition from a raw vulnerability scanner to an intelligent orchestration platform is defined by context. Producing a report stating that "Port 443 is open" or "Software Version X is deployed" provides minimal value. The true value of SMP lies in its ability to automatically assign mathematical risk probabilities to raw data.

This chapter details the `intelligence/` module, the live APIs it queries, and the classical AI algorithms comprising the V9 "Neural Brain."

## 5.1 External Intelligence Feeds

When a scanner (e.g., `Nuclei` or `Nmap`) identifies a vulnerability, it emits a raw finding containing a CVE (Common Vulnerabilities and Exposures) identifier. SMP intercepts this finding before it reaches the database and enriches it against four critical external APIs.

### 5.1.1 The National Vulnerability Database (NVD)
SMP queries the NVD API to retrieve the official CVSS (Common Vulnerability Scoring System) v3.1 vector. This provides the baseline severity score (0.0 to 10.0) based on factors like Attack Vector, Complexity, and Privileges Required.

### 5.1.2 Exploit Prediction Scoring System (EPSS)
CVSS measures the *technical severity* of a vulnerability, but it does not measure *threat*. EPSS is a data-driven model that calculates the probability (0 to 1) that a specific CVE will be actively exploited in the wild within the next 30 days. SMP fetches this score to prioritize remediation. A CVSS 7.0 with an EPSS of 0.95 is vastly more dangerous than a CVSS 9.8 with an EPSS of 0.01.

### 5.1.3 CISA Known Exploited Vulnerabilities (KEV)
The US Cybersecurity and Infrastructure Security Agency (CISA) maintains a definitive catalog of vulnerabilities that have been confirmed to be actively utilized by threat actors. SMP cross-references every CVE against the KEV catalog. If a match is found, a massive mathematical multiplier is applied to the final risk score.

### 5.1.4 The Risk Formula
These data points are ingested into the `tools/risk_scorer.py` module to produce a unified, proprietary risk metric:

```python
# SMP Unified Risk Formula
risk = min(100.0, (cvss / 10.0) * kev_multiplier * greynoise_multiplier * 100.0 + (epss * 30.0))
```
*Where `kev_multiplier` is 2.0 if present on the CISA list, and 1.0 otherwise.*

## 5.2 The Neural Brain: Classical AI Modeling

While external intelligence provides context for isolated CVEs, it fails to analyze the *structural* relationship between vulnerabilities within the target environment. The V9.4.0 Neural Brain engine introduces two classical data science algorithms, written natively in Python without heavy Machine Learning dependencies, to provide deep heuristic insights.

### 5.2.1 Semantic Clustering via TF-IDF
To identify coordinated attack surfaces, SMP must group vulnerabilities that exhibit similar behaviors, even if they were discovered by entirely different scanners. 

The Brain employs a **Term Frequency-Inverse Document Frequency (TF-IDF)** algorithm. 

1. **Tokenization**: The title, description, and OWASP category of every finding are concatenated and tokenized into discrete words.
2. **TF Calculation**: The algorithm measures how frequently a term appears in a specific finding relative to the total words in that finding.
3. **IDF Calculation**: The algorithm measures how rare a term is across the entire set of findings. Words like "the" or "vulnerability" have low IDF scores, while words like "SQL", "Injection", or "Deserialization" have high IDF scores.
4. **Cosine Similarity**: The TF and IDF scores are multiplied to create a mathematical vector for each finding. The engine then calculates the cosine angle between these vectors. 

Findings with a Cosine Similarity score `> 0.4` are dynamically clustered together, allowing the platform to automatically generate insights such as: *"Semantic Attack Cluster Detected: [Authentication, Bypass, JWT] - 14 related findings."*

### 5.2.2 Linchpin Detection via Graph Centrality
Not all vulnerable components are equal. A vulnerable edge-cache server is less critical than a vulnerable core authentication microservice. 

SMP constructs a localized knowledge graph where Nodes are either "Vulnerabilities" or "Affected Components," and Edges are the relationships between them.

To identify the most critical structural weakness, the Brain computes a **Degree Centrality** score (analogous to Google's early PageRank). 

```python
# Conceptual Centrality Scoring
component_score = total_observations / max_observations_in_graph
cve_density = connected_cves / max_cves_in_graph

centrality = min(1.0, component_score + cve_density)
```

Components with a Centrality Score approaching `1.0` are classified as "Linchpins"—structural chokepoints that, if compromised, offer the widest attack surface. 

## 5.3 Real-Time Visual Reactivity

The mathematical outputs of the TF-IDF and Centrality algorithms are piped directly into the `NeuralGraphWidget` (a PySide6 `QGraphicsView` element).

The UI leverages a localized physics engine enforcing Coulomb's Law (repulsion between all nodes) and Hooke's Law (spring attraction along the edges). Furthermore, the UI parses the Centrality score to dynamically scale the physical radius of the nodes, and parses the CVSS severity to apply specific color gradients and glowing radial effects.

Coupled with the thread-safe `EventBus`, the moment a background scan completes, the graph recalculates its centrality weights and visually snaps into a new formation in real-time, providing immediate visual feedback to the security analyst.
