# Chapter 8: Deployment & CI/CD

Distributing an orchestration engine that relies on 50 distinct third-party security tools (written in Go, Python, Ruby, and Perl) across multiple operating systems is a monumental DevOps challenge. This chapter details how SMP achieves cross-platform compatibility through robust bash scripting, containerization, and Continuous Integration pipelines.

## 8.1 The Setup Automation (`setup.sh`)

In the earliest iterations of the platform, installation required the user to manually compile Go binaries, configure Python virtual environments, and install specific system dependencies (`libsqlcipher-dev`, `ruby-dev`, etc.). This process was error-prone and often took hours.

To resolve this, the V6 release introduced a highly advanced, idempotent `setup.sh` installation script. 

### 8.1.1 Idempotency and State Management
The setup script is designed to be executed multiple times without corrupting the environment. It utilizes a `setup.log` file to track state. If the script detects that a specific Go binary (e.g., `nuclei`) is already installed in the local `bin/` directory and matches the required version signature, it bypasses the download, significantly accelerating subsequent runs.

### 8.1.2 Binary Acquisition without Package Managers
A core philosophy of SMP is portability. Rather than relying on OS-level package managers (like `apt` or `brew`) which frequently host outdated versions of security tools, `setup.sh` interacts directly with the GitHub Releases API.

The script determines the host architecture (e.g., `amd64` vs `arm64`) and operating system (`linux` vs `darwin`), dynamically constructs the URL for the latest pre-compiled binary release, downloads the `.tar.gz` or `.zip` archive, verifies its SHA-256 integrity, extracts the binary to the local `bin/` directory, and sets executable permissions. 

This guarantees that SMP always runs on the absolute bleeding-edge versions of external tools, entirely bypassing the limitations of traditional OS repositories.

## 8.2 Containerization (Docker)

While `setup.sh` handles native installations on Linux and macOS, Windows poses a severe challenge. The lack of native support for Bash, combined with the complexities of compiling `pysqlcipher3` on Windows, makes native deployment unviable.

To guarantee true cross-platform compatibility, SMP provides a comprehensive `Dockerfile`.

### 8.2.1 Multi-Stage Dependencies
The Dockerfile is a masterclass in dependency management. It begins by installing the massive underlying system requirements (Python 3.11, build tools, SQLCipher headers, and Ruby). 

Crucially, it utilizes a multi-stage approach for Go binaries. Instead of compiling tools like `subfinder` or `katana` from source—which would require gigabytes of Go toolchains and drastically increase image size—the Dockerfile downloads the pre-compiled Linux binaries directly, mirroring the logic of `setup.sh`.

### 8.2.2 Headless Execution
Because Docker containers lack a display server (X11/Wayland), the PySide6 GUI cannot be launched. The Docker container is strictly configured to execute the platform in Headless API mode (`CMD ["python3", "main.py", "--api"]`). Users interface with the containerized platform entirely via the REST API or via custom orchestration scripts.

## 8.3 Continuous Integration (GitHub Actions)

To ensure that the platform remains stable as complex features like the Neural Brain are introduced, SMP relies heavily on GitHub Actions for Continuous Integration (CI).

On every push to the `main` branch or on every Pull Request, the CI pipeline triggers.

1. **Linting and Syntax Verification**: The pipeline executes `ruff` to ensure strict PEP-8 compliance and instantly fails if undeclared variables or syntax errors are detected.
2. **Architectural Verification**: The pipeline runs `tools/verify_smp.py`. This script performs deep static analysis of the codebase. It verifies that every registered scanner defines a valid DAG dependency, ensures that no cyclic dependencies exist, and confirms that all required template files (like the PDF reporting templates) are present.
3. **Security Audits**: The CI pipeline inherently prevents the introduction of hardcoded credentials or insecure cryptographic implementations by enforcing static analysis checks. 

This rigorous CI/CD pipeline is the fundamental reason SMP can orchestrate 50 external tools concurrently without compromising the stability of the core engine.
