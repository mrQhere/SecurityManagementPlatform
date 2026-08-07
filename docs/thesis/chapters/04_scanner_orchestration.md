# Chapter 4: Scanner Orchestration Engine

The core operational capability of the Security Management Platform is defined by its ability to orchestrate over 50 distinct security tools seamlessly. This chapter details the mechanics of the Directed Acyclic Graph (DAG) task runner, the scanner registry, and the rigid timeout enforcement systems that ensure platform stability.

## 4.1 The Scanner Registry

Integrating a new security tool into a monolithic codebase is typically a fragile process, requiring modifications to centralized execution loops and data parsers. SMP solves this through a decentralized, declarative registry pattern.

Every scanner is a standalone Python module residing in the `scanners/` directory. By utilizing a custom Python decorator (`@register_scanner`), modules declare their metadata, execution constraints, and dependencies at load time.

```python
# The Anatomy of an SMP Scanner
@register_scanner(
    name="SQLMap",
    step_name="Injecting SQL Payloads",
    depends_on=["HTTPx"],
    binary_name="sqlmap",
    needs_binary=True,
    confidence=90
)
def run_sqlmap(target_url: str, scan_id: int = 0, settings: dict = None) -> list:
    # 1. Verification of binary existence
    # 2. Execution of subprocess
    # 3. Parsing of stdout/stderr into standardized dictionary
    # 4. Return findings
```

When SMP initializes, the `core.registry` dynamically imports all modules in the `scanners/` directory. It constructs an internal manifest of available tools, filtering out those whose `binary_name` cannot be located in the system `PATH` or the local `bin/` directory. This allows the platform to degrade gracefully; if `nmap` is missing, the platform logs a warning and bypasses Nmap-dependent tools, rather than crashing.

## 4.2 The Directed Acyclic Graph (DAG) Execution

As established in Chapter 2, SMP relies on a Directed Acyclic Graph to determine the execution order of scanners. 

### 4.2.1 Graph Construction
When a scan is initiated, the `DAGManager` constructs a dependency graph. Nodes represent scanner functions, and directed edges represent the `depends_on` constraints. 

For example:
- `Subfinder` has no dependencies (In-Degree: 0).
- `HTTPx` depends on `Subfinder` (In-Degree: 1).
- `Nuclei` depends on `HTTPx` (In-Degree: 1).

The graph must be acyclic. If Scanner A depends on B, and B depends on A, a cycle exists, and the graph cannot be resolved. The `DAGManager` performs a cycle-detection pass using Depth-First Search (DFS) prior to execution. If a cycle is detected, the scan is aborted, and a critical error is logged, protecting the platform from infinite deadlocks.

### 4.2.2 Multiprocessing Dispatch
Once the graph is validated, the orchestration engine utilizes a `concurrent.futures.ProcessPoolExecutor` to dispatch the nodes. 

```python
# Simplified Orchestration Loop
executor = ProcessPoolExecutor(max_workers=os.cpu_count())
futures = {}

while pending_nodes:
    # Find all nodes whose dependencies have successfully completed
    ready_nodes = get_nodes_with_zero_indegree()
    
    for node in ready_nodes:
        # Submit the scanner function to the process pool
        future = executor.submit(node.execute, target)
        futures[future] = node
        
    # Wait for any process to complete
    done, _ = wait(futures.keys(), return_when=FIRST_COMPLETED)
    
    for future in done:
        completed_node = futures.pop(future)
        # Decrement the in-degree of all nodes that depended on this completed node
        resolve_dependencies(completed_node)
```

This model ensures maximum CPU saturation. If a network-bound tool (like `masscan`) is waiting on I/O, CPU-bound tools (like `gitleaks` parsing a repository) can continue to execute in parallel on separate cores.

## 4.3 Subprocess Isolation and Watchdogs

Security tools are notoriously unstable. They are frequently written by independent researchers, often lack rigorous error handling, and can easily hang when encountering unexpected network states (e.g., tarpits, infinite HTTP redirects).

If SMP invoked these tools synchronously, a single hung `nmap` scan would lock the entire DAG indefinitely. 

To mitigate this, the orchestration engine isolates every tool within a `subprocess.Popen` container wrapped in a rigid `SubprocessWatchdog`.

### 4.3.1 The Watchdog Escalation Protocol
The Watchdog enforces strict time-to-live (TTL) constraints on every execution:

1. **Soft Timeout**: When a tool hits its defined `TIMEOUT` constant, the Watchdog sends a `SIGTERM` (Signal 15) to the process group, requesting graceful termination.
2. **Grace Period**: The Watchdog waits for 5 seconds.
3. **Hard Kill**: If the process has not terminated, the Watchdog escalates to `SIGKILL` (Signal 9), forcefully stripping the process from the kernel scheduler.

```python
# Watchdog execution flow
try:
    process = subprocess.Popen(cmd, preexec_fn=os.setsid)
    stdout, stderr = process.communicate(timeout=MAX_TIMEOUT)
except subprocess.TimeoutExpired:
    os.killpg(os.getpgid(process.pid), signal.SIGTERM)
    time.sleep(5)
    if process.poll() is None: # Process is still alive (Zombie)
        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
```

This ensures that regardless of how catastrophically a third-party security binary fails, the SMP orchestration engine will always reclaim control of the execution thread and proceed with the remainder of the DAG.
