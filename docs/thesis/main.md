---
title: "Security Management Platform: Evolution of a Local-First Intelligence Engine"
author: "mrQhere"
date: "August 2026"
abstract: |
  The landscape of Vulnerability Assessment and Penetration Testing (VAPT) has historically been fragmented across disparate, single-purpose utilities, necessitating extensive manual orchestration by security analysts. While contemporary paradigms have gravitated toward monolithic, cloud-based Security Information and Event Management (SIEM) systems to achieve orchestration, these architectures inherently violate the principle of data sovereignty by requiring the exfiltration of sensitive vulnerability telemetry. 

  This thesis presents the design, mathematical foundations, and implementation of the Security Management Platform (SMP)—a localized, air-gapped threat intelligence engine. By employing a Directed Acyclic Graph (DAG) for concurrent process execution and implementing classical heuristic models (Term Frequency-Inverse Document Frequency and PageRank-style Degree Centrality) natively in Python, SMP achieves enterprise-grade semantic vulnerability clustering and chokepoint detection without reliance on external Large Language Models (LLMs). 

  Furthermore, this paper details the cryptographic architecture utilized to secure the resulting localized intelligence at rest via SQLCipher (AES-256) and Password-Based Key Derivation Function 2 (PBKDF2). The empirical results demonstrate a 73% reduction in orchestration time and a 96.7% reduction in visual alert noise.
documentclass: report
geometry: margin=1in
fontsize: 11pt
toc: true
toc-depth: 2
---

{{ CHAPTER_1 }}

{{ CHAPTER_2 }}

{{ CHAPTER_3 }}

{{ CHAPTER_4 }}

{{ CHAPTER_5 }}

{{ CHAPTER_6 }}

{{ CHAPTER_7 }}

{{ CHAPTER_8 }}

{{ CHAPTER_9 }}

{{ APPENDIX_A }}

{{ APPENDIX_B }}

{{ APPENDIX_C }}

{{ GLOSSARY }}

{{ INDEX }}
