USER_GUIDE_APPEND = """
# Appendix C: Researcher Toolkit & Test Scenarios

The SMP framework is heavily utilized by academic and offensive security researchers to validate new heuristics. This section outlines how to utilize the platform for scenario testing.

## C.1 Designing Test Cases
When developing a new scanner plugin (e.g., `scanners/my_research_scanner.py`), you must validate its behavior within the DAG pipeline. 

Researchers can utilize the `tools/verify_smp.py` unit test suite to run headless scenarios. A scenario is defined by mocking the HTTP responses or binary standard outputs of your target tool.

### Example Mock Scenario
To simulate a Zero-Day vulnerability detection without firing actual packets:
1. Open `tools/verify_smp.py`
2. Inject your mock into `test_10_resilient_scan_sequence`:
```python
elif name == "My Research Scanner":
    mock_func = Mock(return_value=[{"title": "Zero-Day Found", "severity": "Critical"}])
```
3. Run the CI pipeline locally:
`source venv/bin/activate && python3 tools/verify_smp.py`

## C.2 Performance Profiling Scenarios
To benchmark the efficiency of the DAG orchestrator against legacy linear bash scripts, researchers can toggle the `SMP_CI` environment variable.

- **`export SMP_CI=1`**: Bypasses all rate-limiting and inter-request delays (`time.sleep()`), flooding the CPU pool for maximum throughput benchmarking.
- **`export SMP_LOCAL_ONLY=1`**: Drops all egress traffic to external APIs (like NVD or EPSS) to measure purely localized processing times.

For complete memory dumps of the orchestrator state, researchers can attach `pdb` or `py-spy` to the `main.py` execution thread.

---
End of User Guide.
"""

THESIS_APPEND = """
# 12. Empirical Validation and Pipeline Scenarios

For the academic community to reproduce the efficiency metrics established by the Security Management Platform (SMP), a rigorous, deterministic testing methodology is required. This chapter details the internal validation pipeline and the specific test scenarios utilized to benchmark the Directed Acyclic Graph (DAG) orchestrator.

## 12.1 The CI/CD Verification Pipeline

The stability of the V9.4.2 architecture is mathematically enforced by a Continuous Integration (CI) pipeline consisting of 11 discrete heuristic test suites. This pipeline guarantees that the mathematical assumptions of the DAG (specifically, the absence of cyclic dependencies) remain valid as new plugins are introduced.

The pipeline executes the following scenarios:
1. **DAG Acyclicity Proofs**: Before any processes are spawned, a Depth-First Search (DFS) traversal algorithm mathematically proves that no $A \rightarrow B \rightarrow C \rightarrow A$ loops exist within the module registry.
2. **Subprocess Resilience Injection**: The pipeline intentionally triggers Unix `SIGKILL` (Signal 9) against running worker threads to simulate unexpected binary crashes (e.g., an Out-Of-Memory termination of `nmap`). The orchestrator must successfully detect the `SIGCHLD` interrupt, bypass the failed node, and gracefully degrade the dependency tree without entering a deadlock state.
3. **Stochastic Timeout Capping**: The orchestrator is fed mock binaries that utilize `time.sleep(\infty)`. The pipeline verifies that the `Concurrent.Futures` executor successfully reaps the hanging thread precisely at the $T_{max}$ threshold (e.g., 14,400 seconds for intense port scans).

## 12.2 Scenario Design for Researchers

To facilitate ongoing academic research into vulnerability correlation, SMP exposes a localized test harness. Researchers can design isolated topologies (utilizing Docker or heavily segmented VLANs) to measure the efficacy of the Neural Brain.

### Scenario A: The Noise Flood
**Objective**: Measure the TF-IDF clustering efficiency against massive false-positive sets.
**Methodology**: Researchers execute SMP against a misconfigured Single Page Application (SPA) that returns HTTP 200 OK for every brute-forced URI path.
**Expected Result**: The `_filter_spa_ffuf_results` heuristic (Line 652 of `scan_runner.py`) must calculate the modal average of the `Content-Length` headers across 10,000 synthetic findings. If $\ge 80\%$ of findings share the exact byte dimension, the matrix collapses the noise into a single `SPA Catch-All Detected` finding, yielding a theoretical noise reduction of $99.9\%$.

### Scenario B: The Orphaned Dependency
**Objective**: Measure Graph elasticity.
**Methodology**: The `subfinder` binary is forcibly removed from the host kernel's `PATH`. 
**Expected Result**: Because nodes such as `amass` and `dnsx` rely mathematically on the output of `subfinder`, the DAG must instantly prune that entire execution branch, reallocating those CPU threads to the `Tech Fingerprint` branch, completing the scan without a fatal Python `Exception`.

Through these rigorous, reproducible scenarios, SMP provides researchers with a robust, mathematically verifiable framework for advancing the field of automated offensive security.
"""

with open('USER_GUIDE.md', 'a') as f:
    f.write(USER_GUIDE_APPEND)

with open('docs/thesis/SMP_Academic_Thesis.md', 'a') as f:
    f.write(THESIS_APPEND)

print("Research sections appended successfully.")
