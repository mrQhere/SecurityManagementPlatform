# 3. Methodology and System Design

The architectural design of the Security Management Platform is governed by the principles of modularity, decentralization, and hardware abstraction. This chapter details the foundational methodology utilized to construct the orchestration engine and justifies the selection of the core technology stack.

## 3.1 Technological Stack Rationale

The primary requirement for the orchestration engine was the ability to interface reliably with the underlying operating system kernel (to manage POSIX signals for subprocess control) while maintaining rapid development velocity. 

Python (specifically version 3.10 and above) was selected as the foundational language over compiled alternatives such as C++ or Rust. While compiled languages offer superior execution speed, orchestration platforms are inherently I/O bound (waiting on network responses) rather than CPU bound. The minor latency introduced by the Python interpreter is negligible compared to the latency of a network request. Furthermore, Python’s expansive standard library—specifically the `subprocess`, `concurrent.futures`, and `threading` modules—provides a robust, high-level abstraction over OS-level process management, which is critical for the stability of the platform.

For the graphical interface, PySide6 (the official Python bindings for the Qt framework) was chosen over web-based wrappers such as Electron. Electron applications bundle a complete Chromium rendering engine, resulting in severe memory overhead. Qt operates via native C++ rendering, allowing SMP to provide a complex, real-time reactive interface while consuming less than 150MB of system RAM at idle.

## 3.2 The Decentralized Scanner Registry

A fundamental design flaw in many security platforms is the tight coupling between the execution logic and the parser logic. In SMP, the integration of third-party tools is abstracted through a decentralized module registry.

The system utilizes Python decorators to implement a declarative registration pattern. Security researchers develop standalone Python files that reside in the `scanners/` directory. By decorating the execution function with `@register_scanner`, the module declares its metadata at initialization:

```python
@register_scanner(
    name="Nuclei",
    step_name="Executing Nuclei Templates",
    depends_on=["HTTPx", "Nikto"],
    binary_name="nuclei",
    needs_binary=True,
    confidence=95
)
def scan(target_url: str, scan_id: int, settings: dict) -> list:
    # Subprocess execution and parsing logic
```

During application startup, the `core.registry` dynamically imports all modules within the directory. This architecture achieves absolute decoupling; a scanner can be added, modified, or deleted without requiring a single modification to the core orchestration loop.

## 3.3 Event-Driven State Management

Because the orchestration pipeline executes asynchronously across multiple processor cores, state management and UI synchronization present a complex engineering challenge. Updating a graphical element (such as a progress bar) from a background thread typically results in memory corruption or segmentation faults within the Qt framework.

To resolve this, SMP implements a globally accessible `EventBus` utilizing the Publish-Subscribe (PubSub) design pattern.

When a background scanner completes its execution, it does not attempt to mutate the application state directly. Instead, it emits an abstract event (e.g., `EventBus.emit("scan_completed", data)`). The primary UI thread subscribes to this event via a thread-safe Qt Signal/Slot bridge. This methodology guarantees that the heavy computational load of the orchestration engine remains completely isolated from the main event loop, ensuring the UI remains perfectly responsive regardless of the underlying workload.
