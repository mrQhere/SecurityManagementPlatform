<div align="center">

# 🛡️ Security Management Platform (SMP) v5.0

![Platform Overview](https://via.placeholder.com/1200x400.png?text=Security+Management+Platform+v5.0+Enterprise)

**An enterprise-grade, multi-process Security Management Platform utilizing a Directed Acyclic Graph (DAG) for high-performance concurrent vulnerability scanning.**

[![Version](https://img.shields.io/badge/version-5.0.0-blue.svg)](#)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](#)
[![License](https://img.shields.io/badge/license-Proprietary-red.svg)](#)
[![Architecture](https://img.shields.io/badge/architecture-DAG%20%7C%20MVC-success.svg)](#)

</div>

---

## 🚀 Welcome to V5.0: The Concurrency Update

The Security Management Platform has been entirely re-engineered from the ground up. Moving away from legacy sequential scanning, V5.0 introduces true OS-level multiprocessing powered by a smart **Directed Acyclic Graph (DAG)**. 

By calculating tool dependencies in real-time, SMP can now run up to 35 industry-standard security tools concurrently across isolated processes, completely eliminating UI freezing and reducing scan times by up to 80%.

### 🔥 Key V5.0 Features
*   **DAG Orchestration**: Scans now resolve dependency graphs locally, executing non-dependent scanners (like Nmap, Nikto, and SQLMap) in completely parallel Python subprocesses.
*   **Zero-Latency UDP IPC**: Legacy active-polling has been eradicated. The PySide6 UI now listens passively to a zero-latency UDP pub/sub socket (`127.0.0.1:5005`), reducing idle CPU and Disk I/O by over 98%.
*   **Dynamic Plugin Registry**: Developers can now add new scanners instantly via the `@register_scanner` decorator. No manual DAG registration or database schema modifications required!
*   **Strict MVC Architecture**: The massive monolithic UI has been decoupled into elegant `ui/views/` (Mixins) and `ui/controllers/`, keeping business logic and UI rendering perfectly isolated.

---

## 🏗️ System Architecture Deep Dive

SMP V5.0 is built on a highly modular, decoupled architecture designed for scale and stability. The system is split into distinct functional domains to ensure fault tolerance.

### The UI & Event Bus
The frontend is constructed using PySide6. However, unlike traditional desktop applications, the UI does absolutely no heavy lifting. It acts purely as a "dumb" terminal that listens for events. When a background scan completes a task, the Database Manager emits a JSON payload over a local UDP socket (`127.0.0.1:5005`). The UI catches this payload and triggers a Qt Signal, refreshing the screen instantly.

### The DAG Execution Engine
The true power of SMP lies in its Orchestrator. When a scan starts, a new `multiprocessing.Process` is spawned to bypass Python's Global Interpreter Lock (GIL). Inside this process, the Orchestrator analyzes the dependencies of 35 security tools, builds a Directed Acyclic Graph, and launches a ThreadPool to execute them concurrently. If one tool crashes (e.g. out of memory), the Orchestrator safely catches the SIGSEGV and continues executing the remaining branches of the graph.

---

## 💻 Installation & Quick Start

### 1. System Requirements
- **OS**: Linux (Ubuntu 22.04+ recommended)
- **Dependencies**: Everything is handled automatically.

### 2. Automated Zero-Friction Setup
```bash
# Clone the repository
git clone https://github.com/mrQhere/SecurityManagementPlatform.git
cd SecurityManagementPlatform

# Run the fully automated setup script
bash setup.sh
```

### 3. Running Your First Scan
The `setup.sh` script will automatically launch the platform when finished. For future runs, simply execute:
```bash
bash run.sh
```

1. On first boot, create your **Master Password**. This symmetrically encrypts your database (AES-256).
2. Navigate to the **Targets** tab and enter an authorized target URL.
3. Click **Scan**. Watch the terminal output stream in real-time as the DAG Orchestrator parallelizes the attack surface mapping!
4. Click **Report** to generate a comprehensive, executive-ready VAPT PDF.

---

## 🛠️ 35 Integrated Security Modules

SMP acts as a centralized orchestrator for 35 of the world's best open-source security tools (including Nmap, Nuclei, SQLMap, WPScan, Dalfox, etc.). The DAG Engine dynamically maps out their dependencies and executes them concurrently for maximum speed.


---

## 📖 Comprehensive Documentation

For a deep dive into the platform's inner workings, troubleshooting guides, and instructions on how to add your own custom tools using the new Plugin Registry, please consult the **[V5.0 USER GUIDE](./USER_GUIDE.md)**. 

The User Guide contains over 1,000 lines of detailed technical documentation covering every aspect of the platform.

---

## ⚖️ Legal & Copyright

> **CRITICAL NOTICE**: This software is highly proprietary. 
> You are explicitly forbidden from modifying, refactoring, reverse-engineering, or redistributing this code without human consent. 
> By using this software, you accept sole legal responsibility for all activities performed with it. Ensure you have explicit written authorization before scanning any target.

*Security Management Platform (SMP) © Authorised Personnel Only. All Rights Reserved.*
