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
