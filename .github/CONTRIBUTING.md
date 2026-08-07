# Contributing to Security Management Platform (SMP)

First, thank you for your interest in contributing to SMP!

> [!NOTE]
> **Project Status**
> This is a personal project maintained on a best-effort basis. While contributions are welcome, please set your expectations accordingly regarding review times, feature requests, and support.

## Opening an Issue

When opening an issue, please ensure you:
- Check existing issues to avoid duplicates.
- Provide clear steps to reproduce any bugs.
- Include the version of SMP you are running (found in `config/metadata.json`).
- If proposing a feature, explain the problem it solves and why it belongs in the core platform.

## Submitting a Pull Request

If you would like to submit a PR, please follow these steps:

1. **Fork the repository** and create a feature branch (`git checkout -b feature/your-feature`).
2. **Make your changes** following the existing coding style.
3. **Commit your changes** with a clear and descriptive commit message. If applicable, update `CHANGELOG.md` with a plain English description of your changes under the "Unreleased" section.
4. **Run the required CI checks** locally before pushing:
   - Ensure the integrity tests pass: `source venv/bin/activate && python tools/verify_smp.py`
   - Ensure linting passes: `ruff check . --select E,F --ignore E501,F401 --exclude venv,pycache`
5. **Open a Pull Request** against the `main` branch.

### CI Checks Requirement

Your PR will not be merged unless the CI checks pass. Specifically:
- **`tools/verify_smp.py`**: The DAG orchestrator pipeline and database integrity test must pass.
- **`ruff`**: Code must comply with the E and F rulesets (excluding E501 and F401).

Once your PR is open, it requires at least one review before it can be merged.

Thank you for contributing!
