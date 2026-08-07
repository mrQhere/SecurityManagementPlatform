# 4. Algorithmic Implementation

The true complexity of SMP resides in its mathematical execution models and heuristic intelligence engines. This chapter provides a formal algorithmic breakdown of the Directed Acyclic Graph (DAG) orchestration and the "Neural Brain" data science models.

## 4.1 Orchestration via Directed Acyclic Graphs (DAG)

The execution of 50+ disparate security tools cannot occur sequentially, nor can it occur simultaneously, as tools logically depend on the output of preceding tools (e.g., a Directory Brute-Forcer cannot run until an HTTP Prober confirms the port is open). 

SMP models these dependencies as a Directed Acyclic Graph $G = (V, E)$, where $V$ is the set of registered scanner modules (vertices), and $E$ is the set of directed edges representing the `depends_on` constraints. A directed edge $(u, v)$ indicates that scanner $u$ must complete successfully before scanner $v$ can commence.

### 4.1.1 Kahn's Algorithm for Topological Sorting

Before execution begins, the `DAGManager` must determine a valid execution order. It employs Kahn's Algorithm to perform a topological sort of the graph:

1. **Initialization**: Calculate the in-degree (number of incoming edges) for every vertex $v \in V$.
2. **Queueing**: Enqueue all vertices with an in-degree of 0 into a set $S$.
3. **Processing**: While $S$ is not empty:
   - Dequeue a vertex $u$ from $S$ and append it to the topological ordering $L$.
   - For each outgoing edge $(u, v)$ from $u$:
     - Remove the edge from the graph (decrement the in-degree of $v$).
     - If the in-degree of $v$ becomes 0, enqueue $v$ into $S$.
4. **Validation**: If the graph still contains edges after the loop terminates, a cycle exists (e.g., A depends on B, and B depends on A), and the orchestration engine aborts the scan to prevent a deadlock.

### 4.1.2 Concurrent Dispatch

The vertices in set $S$ (nodes with 0 pending dependencies) are immediately dispatched to a `concurrent.futures.ProcessPoolExecutor`. As each process completes, the orchestration engine dynamically decrements the in-degrees of adjacent nodes and dispatches them in real-time, mathematically guaranteeing maximum CPU saturation while strictly respecting logical constraints.

## 4.2 The Neural Brain: Semantic Clustering (TF-IDF)

When the DAG completes, SMP generates thousands of raw, disjointed vulnerabilities. The "Neural Brain" module must computationally determine the semantic relationship between these findings.

To group vulnerabilities by behavior (e.g., grouping all Cross-Site Scripting variations together regardless of which tool found them), the system employs Term Frequency-Inverse Document Frequency (TF-IDF) matrix clustering.

Let $D$ be the corpus of all discovered vulnerabilities. For each vulnerability $d \in D$, the algorithm tokenizes the title, description, and OWASP category into a set of terms $t$.

1. **Term Frequency (TF)**: Measures the local importance of term $t$ in vulnerability $d$.
   $$ \text{TF}(t, d) = \frac{f_{t, d}}{\sum_{t' \in d} f_{t', d}} $$
2. **Inverse Document Frequency (IDF)**: Measures the global rarity of term $t$ across the entire corpus $D$.
   $$ \text{IDF}(t, D) = \log \left( \frac{|D|}{|\{d \in D : t \in d\}|} \right) $$
3. **Vectorization**: The TF-IDF weight for term $t$ in document $d$ is the product:
   $$ w_{t,d} = \text{TF}(t, d) \times \text{IDF}(t, D) $$

Each vulnerability is now represented as an $n$-dimensional mathematical vector. The Neural Brain computes the **Cosine Similarity** between all vectors. Vulnerability pairs exhibiting a Cosine Similarity $> 0.4$ are dynamically clustered, providing the analyst with a consolidated "Attack Chain" rather than isolated alerts.

## 4.3 The Neural Brain: Linchpin Detection (Centrality)

Beyond semantic clustering, the system must identify structural weaknesses in the target topology. SMP constructs an internal threat graph where nodes represent either Vulnerabilities or Affected Network Components (e.g., an IP or a subdomain).

To identify the "Linchpin"—the component that, if compromised, offers the greatest lateral movement capability—the engine calculates a localized Degree Centrality score.

For a given component $C$:
$$ \text{Centrality}(C) = \min \left( 1.0, \frac{\text{Obs}(C)}{\max(\text{Obs})} + \frac{\text{Vuln}(C)}{\max(\text{Vuln})} \right) $$
Where $\text{Obs}(C)$ is the frequency of the component's appearance across all scanner outputs, and $\text{Vuln}(C)$ is the total number of critical CVEs associated directly with that component. 

Components with a Centrality score approaching $1.0$ are flagged by the system, and their corresponding physical nodes in the PySide6 UI are mathematically scaled in radius to instantly draw the analyst's visual focus.
