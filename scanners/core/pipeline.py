from scanners.core.plugin import GenericPlugin

def build_pipeline(url, scan_id, mac_change_ok, resume_status):
    # Dummy precondition for tools requiring MAC anonymization
    def mac_precondition():
        return mac_change_ok
        
    plugins = []
    
    def add_plugin(name, step_name, scan_func, binary_name, process_func, deps, needs_binary=True, precondition=None):
        plugins.append(GenericPlugin(
            target_url=url,
            scan_id=scan_id,
            name=name,
            step_name=step_name,
            depends_on=deps,
            scan_func=scan_func,
            binary_name=binary_name,
            process_func=process_func,
            needs_binary=needs_binary,
            precondition=precondition
        ))
        
    # We will import the actual functions directly inside scan_runner to populate this,
    # or pass them here. Actually, it's better to return a config definition, but since 
    # GenericPlugin takes the actual python functions, let's just construct it in scan_runner.py!
