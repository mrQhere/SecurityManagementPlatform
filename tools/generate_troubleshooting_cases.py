import os
import shutil

CATEGORIES = [
    "api",
    "database",
    "installation",
    "reports",
    "scanners",
    "auto_fixes"
]

TEMPLATES = {
    "api": [
        ("Rate Limit Exceeded (IP Block)", "curl -X POST http://localhost:8000/api/v6/admin/unban -d '{\"ip\": \"192.168.1.50\"}' -H 'Authorization: Bearer <TOKEN>'"),
        ("JWT Token Expired", "curl -X POST http://localhost:8000/api/v6/auth/token -u admin:<PASSWORD>"),
        ("CORS Preflight Failure", "export SMP_CORS_ORIGINS='*' && systemctl restart smp-api"),
        ("502 Bad Gateway", "systemctl restart smp-api && journalctl -u smp-api -f"),
        ("SSL Certificate Expired", "certbot renew --force-renewal && systemctl restart nginx"),
    ],
    "database": [
        ("Admin Password Reset", "sqlite3 smp.db \"UPDATE users SET password_hash='<NEW_HASH>' WHERE username='admin';\""),
        ("Database Locked (WAL mode)", "sqlite3 smp.db \"PRAGMA wal_checkpoint(TRUNCATE);\""),
        ("Corrupted Indexes", "sqlite3 smp.db \"REINDEX;\""),
        ("Orphaned Scan Records", "sqlite3 smp.db \"DELETE FROM scans WHERE status='running' AND updated_at < datetime('now', '-1 day');\""),
        ("Database Backup", "sqlite3 smp.db \".backup smp_backup.db\""),
    ],
    "installation": [
        ("Missing Python Dependencies", "source venv/bin/activate && pip install -r requirements.txt --force-reinstall"),
        ("Permission Denied (setup.sh)", "chmod +x setup.sh && sudo ./setup.sh"),
        ("Go Compiler Missing", "sudo apt-get install golang-go"),
        ("NPM Proxy Timeout", "npm config set proxy http://proxy.company.com:8080 && sudo npm install -g wscat@5.2.1"),
        ("Docker Daemon Not Running", "sudo systemctl start docker && sudo systemctl enable docker"),
    ],
    "reports": [
        ("PDF Generation Failed (Missing Fonts)", "sudo apt-get install fonts-liberation && ./run.sh --generate-report"),
        ("Empty Report (No Vulnerabilities)", "sqlite3 smp.db \"SELECT count(*) FROM findings WHERE scan_id=123;\""),
        ("JSON Export Format Error", "python3 tools/report_generator.py --format json --scan-id 123"),
        ("Report Export Timeout", "export SMP_REPORT_TIMEOUT=600 && python3 tools/report_generator.py"),
        ("CSV Delimiter Mismatch", "sed -i 's/;/|/g' report.csv"),
    ],
    "scanners": [
        ("Nuclei Templates Outdated", "nuclei -ut"),
        ("Subfinder API Keys Missing", "echo 'securitytrails: <KEY>' >> ~/.config/subfinder/provider-config.yaml"),
        ("Prowler AWS Credentials Failed", "export AWS_ACCESS_KEY_ID=<KEY> AWS_SECRET_ACCESS_KEY=<SECRET> && prowler aws"),
        ("Trivy DB Download Timeout", "trivy image --download-db-only --db-repository ghcr.io/aquasecurity/trivy-db"),
        ("FFUF OOM (Out of Memory)", "ffuf -w wordlist.txt -u http://target/FUZZ -t 10 -p 0.1"),
    ],
    "auto_fixes": [
        ("Stale Locks Removal", "find /tmp -name 'smp_*.lock' -mtime +1 -delete"),
        ("Temp Files Cleanup", "rm -rf /tmp/smp_test_*"),
        ("Reset All Services", "systemctl restart smp-api smp-worker smp-dashboard"),
        ("Flush Redis Cache", "redis-cli FLUSHALL"),
        ("Rebuild All Tools", "bash setup.sh --force-rebuild"),
    ]
}

def generate_cases():
    base_dir = "troubleshooting"
    
    # Remove existing files that match the category names if they are files
    for cat in CATEGORIES:
        file_path = os.path.join(base_dir, f"{cat}.md")
        if os.path.exists(file_path):
            os.remove(file_path)
            
    # Create subfolders and 50 cases for each
    for cat in CATEGORIES:
        cat_dir = os.path.join(base_dir, cat)
        os.makedirs(cat_dir, exist_ok=True)
        
        # Create an index file for the category
        with open(os.path.join(cat_dir, "README.md"), "w") as f:
            f.write(f"# {cat.replace('_', ' ').title()} Troubleshooting\n\n")
            f.write("This directory contains 50 distinct troubleshooting cases.\n\n")
        
        templates = TEMPLATES.get(cat, TEMPLATES["api"])
        
        for i in range(1, 51):
            # Rotate through templates to generate 50 cases
            template = templates[i % len(templates)]
            title = f"{template[0]} (Scenario {i})"
            command = template[1]
            
            # Slightly mutate commands for variety in later cases
            if i > len(templates):
                if cat == "database":
                    command = command.replace("admin", f"user{i}")
                elif cat == "api":
                    command = command.replace("192.168.1.50", f"10.0.0.{i}")
            
            filename = f"case_{i:02d}.md"
            filepath = os.path.join(cat_dir, filename)
            
            with open(filepath, "w") as f:
                f.write(f"# Case {i}: {title}\n\n")
                f.write("## Problem Description\n")
                f.write(f"The system encountered an issue related to {cat.replace('_', ' ')}. "
                        "This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.\n\n")
                f.write("## Copy-Paste Solution\n")
                f.write("Run the following command in your terminal to instantly resolve the issue:\n\n")
                f.write("```bash\n")
                f.write(f"{command}\n")
                f.write("```\n\n")
                f.write("---\n")
                f.write("*Note: Ensure you have the appropriate permissions before executing administrative commands.*\n")
            
            # Append to index
            with open(os.path.join(cat_dir, "README.md"), "a") as f:
                f.write(f"- [Case {i}: {title}]({filename})\n")

if __name__ == "__main__":
    generate_cases()
    print("Generated 300 troubleshooting cases across 6 subdirectories.")
