"""
DAG Orchestrator
================
Manages the execution of ScannerPlugins based on their dependencies.
"""
import threading
import queue
import logging
import time

logger = logging.getLogger("smp.scan")

class DAGOrchestrator:
    def __init__(self, plugins, max_workers=3, on_active_change=None):
        self.plugins = {p.name: p for p in plugins}
        self.plugins_lock = threading.Lock()
        self.max_workers = max_workers
        self.on_active_change = on_active_change
        self.completed = set()
        self.failed = set()
        self.running = set()
        self.results = {}
        
    def add_plugin_to_graph(self, plugin):
        """Thread-safe runtime addition of a plugin to the DAG."""
        with self.plugins_lock:
            self.plugins[plugin.name] = plugin
            logger.info(f"Dynamically added {plugin.name} to DAG orchestrator.")
        
    def get_executable_plugins(self):
        """Returns a list of plugins that are ready to run (all dependencies met)."""
        executable = []
        with self.plugins_lock:
            plugins_items = list(self.plugins.items())
            
        for name, plugin in plugins_items:
            if name in self.completed or name in self.failed or name in self.running:
                continue
            
            # Check if all dependencies are satisfied (either completed successfully or failed)
            deps_met = True
            for dep in plugin.depends_on:
                if dep not in self.completed and dep not in self.failed:
                    deps_met = False
                    break
            
            if deps_met:
                executable.append(plugin)
                
        return executable

    def run(self, cancel_event=None):
        """Executes the DAG using a process pool."""
        logger.info(f"Starting DAG Orchestrator with {len(self.plugins)} plugins.")
        
        # Initialize a queue for results
        result_queue = queue.Queue()
        threads = {}
        start_times = {}
        
        def run_plugin(plugin, q, c_event):
            try:
                # Basic cancellation check
                if c_event and c_event.is_set():
                    q.put((plugin.name, None, False, "Cancelled"))
                    return
                
                # ── V7.0 — Inter-Request Delay (Rate Limiting) ────────────────
                # Stagger concurrent tool launches to avoid hammering the target.
                import time
                import random
                time.sleep(random.uniform(1.0, 3.0))
                    
                # Setup resilient subprocess execution context here if needed...
                res = plugin.execute()
                
                if res is not None:
                    plugin.process_results(res)
                    q.put((plugin.name, res, True, None))
                else:
                    q.put((plugin.name, None, False, "Execution failed or returned None"))
            except Exception as e:
                logger.error(f"[{plugin.step_name}] Execution exception: {e}")
                q.put((plugin.name, None, False, str(e)))
        
        while True:
            with self.plugins_lock:
                total_plugins = len(self.plugins)
            if len(self.completed) + len(self.failed) >= total_plugins:
                break
            if cancel_event and cancel_event.is_set():
                logger.warning("DAG Orchestrator cancelled by user.")
                break
                
            # Start new processes if we have capacity and ready plugins
            ready_plugins = self.get_executable_plugins()
            
            while len(self.running) < self.max_workers and ready_plugins:
                plugin = ready_plugins.pop(0)
                self.running.add(plugin.name)
                if self.on_active_change:
                    with self.plugins_lock:
                        active_step_names = [self.plugins[p].step_name for p in self.running if p in self.plugins]
                    self.on_active_change(active_step_names)
                
                t = threading.Thread(
                    target=run_plugin, 
                    args=(plugin, result_queue, cancel_event),
                    name=f"DAGWorker_{plugin.name}",
                    daemon=True
                )
                threads[plugin.name] = t
                t.start()
                start_times[plugin.name] = time.time()
                logger.info(f"Started plugin: {plugin.name}")

            # Wait for at least one thread to finish or just poll
            if self.running:
                try:
                    # Blocking get with timeout allows us to check for cancellation
                    name, res, success, err = result_queue.get(timeout=1.0)
                    self.running.remove(name)
                    if self.on_active_change:
                        with self.plugins_lock:
                            active_step_names = [self.plugins[p].step_name for p in self.running if p in self.plugins]
                        self.on_active_change(active_step_names)
                    
                    if success:
                        self.completed.add(name)
                        self.results[name] = res
                        logger.info(f"Plugin completed: {name}")
                    else:
                        self.failed.add(name)
                        logger.error(f"Plugin failed: {name} - {err}")
                        
                    # Clean up thread handle
                    if name in threads:
                        threads[name].join()
                        del threads[name]
                except queue.Empty:
                    current_time = time.time()
                    for r_name in list(self.running):
                        if current_time - start_times.get(r_name, current_time) > 3600:
                            logger.error(f"[{r_name}] CRITICAL: Plugin timed out after 60 minutes. Moving on.")
                            self.running.remove(r_name)
                            self.failed.add(r_name)
                            if r_name in threads:
                                # We can't safely kill the thread, but we can stop tracking it
                                del threads[r_name]
                    continue
            else:
                # If we have no running processes and no ready plugins, 
                # we have a dependency deadlock or unresolvable failure graph.
                with self.plugins_lock:
                    total_plugins = len(self.plugins)
                if len(self.completed) + len(self.failed) < total_plugins:
                    logger.error("DAG Orchestrator Deadlock: Cannot resolve remaining dependencies.")
                    break
        
        # Threads can't be strictly 'killed', but since they are daemons and we check cancel_event, they will exit.
        return self.results
