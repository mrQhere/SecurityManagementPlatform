<div align="center">

# 🛡️ Security Management Platform (SMP) V6.0 🛡️

**The Complete Enterprise Security Orchestrator**

[![Version](https://img.shields.io/badge/Version-V6.0-blueviolet?style=for-the-badge&logo=shield)](.)
[![Status](https://img.shields.io/badge/Status-Production-brightgreen?style=for-the-badge)](.)
[![License](https://img.shields.io/badge/License-Proprietary-red?style=for-the-badge)](.)

</div>

---

## 🌟 What is SMP?

Security Management Platform (SMP) V6.0 is a proprietary, all-in-one vulnerability scanning and intelligence orchestration platform designed exclusively for Mega Cooperative.

It brings together **30+ security tools**, **CVE intelligence**, **compliance mapping**, and **executive reporting** into a single, beautiful dashboard.

---

## 🔥 Key Features in V6.0

*   **Zero-Friction Plugin Architecture**: Drop any scanner in the `scanners/` directory and it auto-registers.
*   **Encrypted Database**: AES-256 (Fernet) + PBKDF2 (600,000 iterations).
*   **Secured REST API**: Headless operation via FastAPI + JWT Auth + Rate Limiting.
*   **Intelligence & OSINT**: GreyNoise IP intelligence, real-time CVE syncing.
*   **Compliance Ready**: Automated mapping to OWASP Top 10 2021, CIS Controls v8, and ISO 27001:2022.
*   **SBOM Generation**: Automatic CycloneDX Software Bill of Materials.
*   **OPSEC Safe**: Dynamic MAC address changing and port baselining.

---

## 🚀 Quick Start

1. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
2. **Run**:
   ```bash
   python3 main.py
   ```

> 📚 **Want the full story?** Check out the beautifully crafted [USER_GUIDE.md](USER_GUIDE.md) for a complete walkthrough from beginner to research level!

---

> **⚠️ LEGAL NOTICE**
> This software is proprietary and strictly for authorized personnel of Mega Cooperative. Unauthorized access, modification, or distribution is strictly prohibited.
