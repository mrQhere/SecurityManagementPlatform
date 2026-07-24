# SMP V6.5 — Upgrade Task List

## Status Legend
- [x] Done
- [ ] Pending
- [~] In Progress

---

## 1. Version Bump — V6.0 → V6.5
- [x] `config/metadata.json` — version updated
- [x] `main.py` — header updated
- [x] `run.sh` — version string updated
- [x] `api/server.py` — version updated
- [x] `LICENSE` — version updated
- [x] `SECURITY.md` — version updated
- [ ] `README.md` — update version
- [ ] `USER_GUIDE.md` — update version
- [ ] `setup.sh` — update version comment
- [ ] `Dockerfile` — update LABEL version
- [ ] All scanner docstrings — bulk sed pass

---

## 2. Cleanup — Remove Unneeded Files
- [x] `LICENSE_FINDER.md` — deleted
- [x] `license_puzzle/` — deleted
- [x] `wordlists/` — deleted (unused)
- [x] `pentestgpt_repo/` — deleted (temp clone)
- [x] `scratch_remote_repo/` — deleted (temp clone)
- [ ] `setup.bat` — Windows setup (keep or remove — confirm with user)
- [ ] `setup.ps1` — Windows PowerShell setup (keep or remove — confirm with user)

---

## 3. New Scanners Added
- [x] `scanners/gobuster.py` — dir + dns brute-force
- [x] `scanners/dirb.py` — classic web content discovery
- [x] `scanners/netcat_probe.py` — TCP banner grabbing

---

## 4. New Core Modules Added
- [x] `tools/narrative_logger.py` — live walkthrough narrator
- [x] `tools/dynamic_pipeline.py` — adaptive stage-feeding pipeline

---

## 5. Docker / Deployment
- [x] `Dockerfile` — created (Ubuntu 22.04, all tools, Go tools, Python)
- [x] `docker-compose.yml` — created (named volumes, health check)
- [x] `Makefile` — created (build, run, stop, logs, shell targets)
- [ ] `Dockerfile` — add gobuster + dirb (DONE via sed)
- [ ] `.dockerignore` — create to exclude venv, .git, logs

---

## 6. setup.sh — Update for New Tools
- [ ] Add `gobuster` to apt install block
- [ ] Add `dirb` to apt install block
- [ ] Add `netcat-openbsd` to apt install block
- [ ] Update version comment to V6.5

---

## 7. Attribution — "Made by mrQhere"
- [x] `main.py` — header comment updated
- [x] `api/server.py` — API description updated
- [x] `tools/sbom_generator.py` — vendor updated
- [x] `README.md` — maintainer link added
- [x] `LICENSE` — copyright updated to mrQhere
- [x] `SECURITY.md` — contact updated to GitHub
- [ ] Add footer comment to each new module

---

## 8. Documentation
- [x] `README.md` — rewritten (professional, no emojis)
- [x] `SECURITY.md` — rewritten
- [x] `LICENSE` — rewritten with mrQhere
- [ ] `README.md` — update to V6.5, add new tools/features
- [ ] `SECURITY.md` — update to V6.5
- [ ] `USER_GUIDE.md` — **FULL REWRITE** (1600+ lines, Apple-design aesthetic)
  - [ ] Part 0: Philosophy & Architecture
  - [ ] Part 1: Setup (Beginner — full walkthrough, copy-paste commands)
  - [ ] Part 2: First Run & Daily Operations
  - [ ] Part 3: Intermediate — Pipeline, Tools, How It Works
  - [ ] Part 4: Advanced — Core Internals, DB schema, IPC, Encryption
  - [ ] Part 5: Adding Custom Scanners
  - [ ] Part 6: REST API Reference
  - [ ] Part 7: Troubleshooting — 40 errors with commands
  - [ ] Part 8: Future Roadmap — V7, V8, V9

---

## 9. GitHub Push Prep
- [ ] Verify `.gitignore` excludes: `venv/`, `database/*.db`, `*.enc`, `logs/`, `reports/`, `cache/port_baselines/`
- [ ] Run `git status` to confirm clean tree
- [ ] Create `git tag v6.5`
- [ ] Push to `https://github.com/mrQhere/SecurityManagementPlatform.git`

---

## Priority Order
1. USER_GUIDE.md full rewrite
2. setup.sh update (new tools)
3. README.md + SECURITY.md version bump
4. .dockerignore creation
5. Footer attribution on new modules
6. Git tag + push
