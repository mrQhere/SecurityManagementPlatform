# Data Integrity Note

`database/global_intel.db` was regenerated on 2026-08-07 from live CISA
KEV data only, replacing a version that contained ~9,000 fabricated
synthetic CVE records (random IDs, random CVSS/EPSS scores) added
by a since-removed function in `tools/seed_intel.py`.

The fabricated version remains recoverable from git history at
these commits (NOT rewritten, by design — history rewrite requires
a manual decision, not an automated one):

```
b1629d7 chore: Snapshot auto-update to V9.3.3 - Feat: Built Obsidian-style Force-Directed Neural Graph UI and massive 10K+ data intelligence expansion
10b1818 chore: Snapshot auto-update to V9.3.3 - Seeded V9 Intelligence Brain with 2200+ real-world CISA KEV and historical vulnerabilities
197a522 chore: Snapshot auto-update to V9.3.3 - The V9.3.3 Awakening: Global Intelligence DB Pre-populated and test suite isolated
80acb7a chore: Snapshot auto-update to V9.3.3 - Integrated V9 Neural Correlation Engine (Brain) and crowdsourced global intel database
```

Anyone who cloned the repo before 2026-08-07 and has not re-pulled may
still have the fabricated file locally.

## Regenerated file properties

- **Source**: Live CISA Known Exploited Vulnerabilities (KEV) catalog
- **Row count**: 1,661 entries (real KEV records as of 2026-08-07)
- **Table**: `global_heuristics`
- **CVSS / EPSS**: Set to `0.0` intentionally — real values are populated
  at scan-time by `intelligence/nvd.py` and `intelligence/epss.py`.
  Do not add fabricated scores back.
- **Regeneration command**: `python tools/seed_intel.py`
