## Summary
<!-- One sentence: what does this PR do? -->

## Type of change
- [ ] Bug fix
- [ ] New scanner module
- [ ] Documentation
- [ ] Dependency update
- [ ] Refactor / internal improvement

## Scanner module checklist (if applicable)
- [ ] Follows the contract in [CONTRIBUTING.md](CONTRIBUTING.md)
- [ ] `depends_on` set correctly in DAG
- [ ] `confidence` score set
- [ ] Timeout preserved (not reduced from baseline)
- [ ] `return None` on binary not found, `return []` on no findings

## General checklist
- [ ] `python tools/verify_smp.py -v` passes locally
- [ ] No hardcoded credentials, IPs, or tokens
- [ ] No fabricated/simulated data in seeds or tests
- [ ] Self-reviewed — no stray debug prints

## Related issues
Closes #
