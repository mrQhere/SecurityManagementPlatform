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

\newpage
