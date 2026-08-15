import os
import json
import shutil
import datetime
import urllib.parse
from tools.db_manager import get_db_connection

def export_target_data(target_url):
    """
    Exports data for a specific target URL, including DB records, reports, and logs.
    Packages them into a ZIP archive for  ticketing systems.
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    # Sanitize URL for filename
    safe_url = target_url.replace("https://", "").replace("http://", "").replace("/", "_")
    staging_dir = f"SMP_{safe_url}_Export_{timestamp}"
    
    if os.path.exists(staging_dir):
        shutil.rmtree(staging_dir)
    os.makedirs(staging_dir)
    
    db_dump_path = os.path.join(staging_dir, f"smp_{safe_url}_data.json")
    export_data = {"target_url": target_url, "export_date": timestamp}
    
    try:
        conn = get_db_connection()
        # Get target ID
        target_row = conn.execute("SELECT * FROM targets WHERE url = ?", (target_url,)).fetchone()
        if not target_row:
            return None, f"Target {target_url} not found in database."
        
        target_id = target_row["id"]
        export_data["target"] = dict(target_row)
        
        # Get Scans
        scans = conn.execute("SELECT * FROM scans WHERE target_id = ?", (target_id,)).fetchall()
        scan_ids = [s["id"] for s in scans]
        export_data["scans"] = [dict(s) for s in scans]
        
        if scan_ids:
            placeholders = ",".join("?" * len(scan_ids))
            # Get findings
            findings = conn.execute(f"SELECT * FROM findings WHERE scan_id IN ({placeholders})", scan_ids).fetchall()
            export_data["findings"] = [dict(f) for f in findings]
            
            # Get technologies
            techs = conn.execute(f"SELECT * FROM technologies WHERE scan_id IN ({placeholders})", scan_ids).fetchall()
            export_data["technologies"] = [dict(t) for t in techs]
            
            # Get risk scores
            scores = conn.execute(f"SELECT * FROM risk_scores WHERE scan_id IN ({placeholders})", scan_ids).fetchall()
            export_data["risk_scores"] = [dict(s) for s in scores]
            
            # Get raw scan outputs
            raw_outputs = conn.execute(f"SELECT * FROM raw_scan_output WHERE scan_id IN ({placeholders})", scan_ids).fetchall()
            export_data["raw_scan_output"] = [dict(r) for r in raw_outputs]
            
        # Get Logs specific to this target
        # Logs usually contain the URL in the message
        like_url = f"%{target_url}%"
        logs = conn.execute("SELECT * FROM logs WHERE message LIKE ?", (like_url,)).fetchall()
        export_data["logs"] = [dict(l) for l in logs]
        
        conn.close()
        
        with open(db_dump_path, "w", encoding="utf-8") as f:
            json.dump(export_data, f, indent=4)
            
    except Exception as e:
        with open(os.path.join(staging_dir, "DB_EXPORT_ERROR.txt"), "w") as f:
            f.write(f"Failed to export DB: {e}")
            
    # Copy Reports matching target
    reports_staging = os.path.join(staging_dir, "reports")
    os.makedirs(reports_staging, exist_ok=True)
    
    # SMP report naming convention: SMP_target.com_Report_...
    for ext_dir in ["pdf", "html", "sbom"]:
        src_dir = os.path.join("reports", ext_dir)
        if os.path.exists(src_dir):
            for fname in os.listdir(src_dir):
                if safe_url in fname or urllib.parse.quote(target_url) in fname:
                    shutil.copy2(os.path.join(src_dir, fname), os.path.join(reports_staging, fname))
                    
    # Generate README footer
    readme_path = os.path.join(staging_dir, "README.txt")
    with open(readme_path, "w", encoding="utf-8") as f:
        f.write(f"Security Management Platform -  Data Export for {target_url}\n")
        f.write("====================================================================\n\n")
        f.write(f"Export Date: {timestamp}\n")
        f.write("Contents:\n")
        f.write(f"- smp_{safe_url}_data.json: Decrypted database dump (findings, scans, raw_scan_output, target logs)\n")
        f.write("- reports/: All generated PDF, HTML, and SBOM compliance reports for this target\n\n")
        f.write("Scanned by SMP - Security Management Platform\n")

    # Zip and Cleanup
    zip_filename = f"SMP_Export_{safe_url}_{timestamp}"
    shutil.make_archive(zip_filename, 'zip', staging_dir)
    shutil.rmtree(staging_dir)
    
    return True, f"{zip_filename}.zip"
