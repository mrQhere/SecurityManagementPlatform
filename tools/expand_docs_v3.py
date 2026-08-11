import os

USER_GUIDE_APPEND = """
# Appendix D: Distributed Kubernetes Deployment (Theoretical)
For organizations exceeding the limitations of a single localized workstation, SMP is designed for distributed microservice scaling. 

## D.1 The Hub-and-Spoke Architecture
By wrapping the 55 scanners within individual containerized instances, SMP acts as the central orchestration hub. 
- **The Brain Node**: Handles PostgreSQL (replacing SQLite) and TF-IDF clustering.
- **The Worker Nodes**: Deployed across segmented VPNs or VLANs. They pull execution tasks via an internal Redis queue.

### Example `docker-compose.prod.yml` Snippet
```yaml
version: '3.8'
services:
  smp-core:
    image: smp/core:v9.4
    environment:
      - DISTRIBUTED_MODE=1
      - REDIS_URL=redis://smp-cache:6379
    volumes:
      - ./data:/app/database
```

# Appendix E: Custom Deduplication Tuning
You can manually adjust the Levenshtein distance thresholds in `config/settings.json` to alter how aggressively SMP merges findings.
- `dedup_ratio: 0.95` -> Extremely strict. Only merges exactly identical strings. (Results in higher noise).
- `dedup_ratio: 0.65` -> Very loose. Will aggressively merge related vulnerabilities. (Risk of merging unrelated vectors).

---
"""

THESIS_APPEND = """
# 13. Advanced Threat Modeling with Attack Trees

To move beyond isolated vulnerability discovery, the future roadmap of the Security Management Platform integrates formal Attack Tree generation.

## 13.1 Boolean Logic Gates in Threat Graphs
Instead of merely flagging that `Port 22 is open` and `CVE-2021-3156 (Sudo)` is present, SMP utilizes Boolean logic gates to trace exploit chains.
- **AND Gates**: An attacker requires *both* a valid credential dump (from `ffuf` or `sqlmap`) AND an accessible administrative portal to achieve RCE.
- **OR Gates**: An attacker can achieve initial access via a weak SSH password OR a vulnerable public-facing Jenkins instance.

By calculating the path of least resistance through these Boolean gates (often utilizing Dijkstra's shortest-path algorithm weighted by CVSS scores), the Neural Brain automatically identifies the mathematically easiest path to domain compromise.

# 14. Quantum-Resistant Cryptography Integration

As VAPT telemetry represents highly sensitive intelligence, it must be protected against future cryptographic obsolescence ("Store Now, Decrypt Later" attacks by nation-state actors).

## 14.1 The Transition from AES to Lattice-Based Cryptography
While AES-256 currently provides adequate security against Shor's algorithm on theoretical quantum computers, SMP's roadmap (V11) proposes integrating the CRYSTALS-Kyber algorithm for key encapsulation during distributed node-to-node telemetry exchange. 
This ensures that intercepted orchestration traffic remains computationally secure across the next three decades of cryptographic advancement.
"""

with open('USER_GUIDE.md', 'a') as f:
    f.write(USER_GUIDE_APPEND)

with open('docs/thesis/SMP_Academic_Thesis.md', 'a') as f:
    f.write(THESIS_APPEND)
