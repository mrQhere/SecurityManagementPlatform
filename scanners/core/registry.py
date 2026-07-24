import os
import pkgutil
import importlib
import logging
from .plugin import ScannerPlugin

logger = logging.getLogger("smp.scan.registry")

_REGISTRY = {}

def register_scanner(name, step_name, depends_on, binary_name, needs_binary=True, confidence=50):
    """
    Decorator to register a scanner function into the global DAG registry.
    
    @register_scanner(
        name="Nmap", 
        step_name="Running Nmap", 
        depends_on=["Traceroute"], 
        binary_name="nmap", 
        needs_binary=True,
        confidence=90
    )
    def run_nmap_scan(url): ...
    """
    def decorator(func):
        _REGISTRY[name] = {
            "name": name,
            "step_name": step_name,
            "depends_on": depends_on,
            "scan_func": func,
            "binary_name": binary_name,
            "needs_binary": needs_binary,
            "confidence": confidence
        }
        return func
    return decorator

def _load_plugin_meta(modname: str, module) -> bool:
    """
    V6.5 — Zero-Friction Plugin Registration.
    
    If a scanner module has a PLUGIN_META dict, auto-register it.
    
    Minimum required PLUGIN_META:
        PLUGIN_META = {
            "name": "MyTool",           # Display name
            "binary": "mytool",         # Binary to check for on PATH
            "severity": "Medium",       # Default severity if not specified by scan
        }
    
    Optional PLUGIN_META keys:
        "step_name"  : "Running MyTool"  (defaults to "Running {name}")
        "depends_on" : ["Nmap"]          (list of scanners that must run first)
        "confidence" : 70               (0-100)
        "enabled"    : True
    """
    meta = getattr(module, "PLUGIN_META", None)
    if not meta or not isinstance(meta, dict):
        return False

    name = meta.get("name")
    if not name:
        logger.warning(f"[Registry] Plugin {modname} has PLUGIN_META but no 'name'. Skipped.")
        return False

    # Check for a scan() function
    scan_func = getattr(module, "scan", None) or getattr(module, "run_scan", None)
    if not scan_func:
        logger.warning(f"[Registry] Plugin {modname} ({name}) has no scan() or run_scan() function. Skipped.")
        return False

    if name in _REGISTRY:
        return True  # Already registered via decorator

    _REGISTRY[name] = {
        "name": name,
        "step_name": meta.get("step_name", f"Running {name}"),
        "depends_on": meta.get("depends_on", []),
        "scan_func": scan_func,
        "binary_name": meta.get("binary", name.lower()),
        "needs_binary": meta.get("needs_binary", True),
        "confidence": meta.get("confidence", 60),
        "plugin_meta": meta,
        "auto_discovered": True,
    }
    logger.info(f"[Registry] ✓ Auto-registered plugin: '{name}' from {modname}")
    return True


def discover_scanners():
    """Auto-discover and import all python files in the scanners/ directory.
    V6.5: Also checks for PLUGIN_META for zero-config plug-and-play scanners.
    """
    import scanners
    package = scanners
    prefix = package.__name__ + "."
    for importer, modname, ispkg in pkgutil.iter_modules(package.__path__, prefix):
        if not ispkg and modname != "scanners.scan_runner" and not modname.startswith("scanners.core"):
            try:
                module = importlib.import_module(modname)
                # V6.5: Try PLUGIN_META auto-registration
                _load_plugin_meta(modname, module)
            except Exception as e:
                logger.error(f"Failed to load scanner module {modname}: {e}")


def auto_discover_plugins() -> list:
    """
    V6.5 — Explicitly trigger plugin auto-discovery and return list of newly found plugins.
    Called on startup and can be called again if new scanners are dropped in.
    """
    before = set(_REGISTRY.keys())
    discover_scanners()
    after = set(_REGISTRY.keys())
    new_plugins = list(after - before)
    if new_plugins:
        logger.info(f"[Registry] {len(new_plugins)} new plugin(s) auto-discovered: {new_plugins}")
    return new_plugins


def get_registered_scanners():
    """Returns the dictionary of registered scanners."""
    if not _REGISTRY:
        discover_scanners()
    return _REGISTRY
