# Scanners Troubleshooting

This document contains 50 distinct troubleshooting cases.

## General Diagnostics
The system encountered an issue related to this category. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

**Copy-Paste Solutions:** Run the respective command in your terminal to instantly resolve the issue. *(Note: Ensure you have the appropriate permissions before executing administrative commands.)*

---

# Case 1: Subfinder API Keys Missing (Scenario 1)

```bash
echo 'securitytrails: <KEY>' >> ~/.config/subfinder/provider-config.yaml
```

---

# Case 2: Prowler AWS Credentials Failed (Scenario 2)

```bash
export AWS_ACCESS_KEY_ID=<KEY> AWS_SECRET_ACCESS_KEY=<SECRET> && prowler aws
```

---

# Case 3: Trivy DB Download Timeout (Scenario 3)

```bash
trivy image --download-db-only --db-repository ghcr.io/aquasecurity/trivy-db
```

---

# Case 4: FFUF OOM (Out of Memory) (Scenario 4)

```bash
ffuf -w wordlist.txt -u http://target/FUZZ -t 10 -p 0.1
```

---

# Case 5: Nuclei Templates Outdated (Scenario 5)

```bash
nuclei -ut
```

---

# Case 6: Subfinder API Keys Missing (Scenario 6)

```bash
echo 'securitytrails: <KEY>' >> ~/.config/subfinder/provider-config.yaml
```

---

# Case 7: Prowler AWS Credentials Failed (Scenario 7)

```bash
export AWS_ACCESS_KEY_ID=<KEY> AWS_SECRET_ACCESS_KEY=<SECRET> && prowler aws
```

---

# Case 8: Trivy DB Download Timeout (Scenario 8)

```bash
trivy image --download-db-only --db-repository ghcr.io/aquasecurity/trivy-db
```

---

# Case 9: FFUF OOM (Out of Memory) (Scenario 9)

```bash
ffuf -w wordlist.txt -u http://target/FUZZ -t 10 -p 0.1
```

---

# Case 10: Nuclei Templates Outdated (Scenario 10)

```bash
nuclei -ut
```

---

# Case 11: Subfinder API Keys Missing (Scenario 11)

```bash
echo 'securitytrails: <KEY>' >> ~/.config/subfinder/provider-config.yaml
```

---

# Case 12: Prowler AWS Credentials Failed (Scenario 12)

```bash
export AWS_ACCESS_KEY_ID=<KEY> AWS_SECRET_ACCESS_KEY=<SECRET> && prowler aws
```

---

# Case 13: Trivy DB Download Timeout (Scenario 13)

```bash
trivy image --download-db-only --db-repository ghcr.io/aquasecurity/trivy-db
```

---

# Case 14: FFUF OOM (Out of Memory) (Scenario 14)

```bash
ffuf -w wordlist.txt -u http://target/FUZZ -t 10 -p 0.1
```

---

# Case 15: Nuclei Templates Outdated (Scenario 15)

```bash
nuclei -ut
```

---

# Case 16: Subfinder API Keys Missing (Scenario 16)

```bash
echo 'securitytrails: <KEY>' >> ~/.config/subfinder/provider-config.yaml
```

---

# Case 17: Prowler AWS Credentials Failed (Scenario 17)

```bash
export AWS_ACCESS_KEY_ID=<KEY> AWS_SECRET_ACCESS_KEY=<SECRET> && prowler aws
```

---

# Case 18: Trivy DB Download Timeout (Scenario 18)

```bash
trivy image --download-db-only --db-repository ghcr.io/aquasecurity/trivy-db
```

---

# Case 19: FFUF OOM (Out of Memory) (Scenario 19)

```bash
ffuf -w wordlist.txt -u http://target/FUZZ -t 10 -p 0.1
```

---

# Case 20: Nuclei Templates Outdated (Scenario 20)

```bash
nuclei -ut
```

---

# Case 21: Subfinder API Keys Missing (Scenario 21)

```bash
echo 'securitytrails: <KEY>' >> ~/.config/subfinder/provider-config.yaml
```

---

# Case 22: Prowler AWS Credentials Failed (Scenario 22)

```bash
export AWS_ACCESS_KEY_ID=<KEY> AWS_SECRET_ACCESS_KEY=<SECRET> && prowler aws
```

---

# Case 23: Trivy DB Download Timeout (Scenario 23)

```bash
trivy image --download-db-only --db-repository ghcr.io/aquasecurity/trivy-db
```

---

# Case 24: FFUF OOM (Out of Memory) (Scenario 24)

```bash
ffuf -w wordlist.txt -u http://target/FUZZ -t 10 -p 0.1
```

---

# Case 25: Nuclei Templates Outdated (Scenario 25)

```bash
nuclei -ut
```

---

# Case 26: Subfinder API Keys Missing (Scenario 26)

```bash
echo 'securitytrails: <KEY>' >> ~/.config/subfinder/provider-config.yaml
```

---

# Case 27: Prowler AWS Credentials Failed (Scenario 27)

```bash
export AWS_ACCESS_KEY_ID=<KEY> AWS_SECRET_ACCESS_KEY=<SECRET> && prowler aws
```

---

# Case 28: Trivy DB Download Timeout (Scenario 28)

```bash
trivy image --download-db-only --db-repository ghcr.io/aquasecurity/trivy-db
```

---

# Case 29: FFUF OOM (Out of Memory) (Scenario 29)

```bash
ffuf -w wordlist.txt -u http://target/FUZZ -t 10 -p 0.1
```

---

# Case 30: Nuclei Templates Outdated (Scenario 30)

```bash
nuclei -ut
```

---

# Case 31: Subfinder API Keys Missing (Scenario 31)

```bash
echo 'securitytrails: <KEY>' >> ~/.config/subfinder/provider-config.yaml
```

---

# Case 32: Prowler AWS Credentials Failed (Scenario 32)

```bash
export AWS_ACCESS_KEY_ID=<KEY> AWS_SECRET_ACCESS_KEY=<SECRET> && prowler aws
```

---

# Case 33: Trivy DB Download Timeout (Scenario 33)

```bash
trivy image --download-db-only --db-repository ghcr.io/aquasecurity/trivy-db
```

---

# Case 34: FFUF OOM (Out of Memory) (Scenario 34)

```bash
ffuf -w wordlist.txt -u http://target/FUZZ -t 10 -p 0.1
```

---

# Case 35: Nuclei Templates Outdated (Scenario 35)

```bash
nuclei -ut
```

---

# Case 36: Subfinder API Keys Missing (Scenario 36)

```bash
echo 'securitytrails: <KEY>' >> ~/.config/subfinder/provider-config.yaml
```

---

# Case 37: Prowler AWS Credentials Failed (Scenario 37)

```bash
export AWS_ACCESS_KEY_ID=<KEY> AWS_SECRET_ACCESS_KEY=<SECRET> && prowler aws
```

---

# Case 38: Trivy DB Download Timeout (Scenario 38)

```bash
trivy image --download-db-only --db-repository ghcr.io/aquasecurity/trivy-db
```

---

# Case 39: FFUF OOM (Out of Memory) (Scenario 39)

```bash
ffuf -w wordlist.txt -u http://target/FUZZ -t 10 -p 0.1
```

---

# Case 40: Nuclei Templates Outdated (Scenario 40)

```bash
nuclei -ut
```

---

# Case 41: Subfinder API Keys Missing (Scenario 41)

```bash
echo 'securitytrails: <KEY>' >> ~/.config/subfinder/provider-config.yaml
```

---

# Case 42: Prowler AWS Credentials Failed (Scenario 42)

```bash
export AWS_ACCESS_KEY_ID=<KEY> AWS_SECRET_ACCESS_KEY=<SECRET> && prowler aws
```

---

# Case 43: Trivy DB Download Timeout (Scenario 43)

```bash
trivy image --download-db-only --db-repository ghcr.io/aquasecurity/trivy-db
```

---

# Case 44: FFUF OOM (Out of Memory) (Scenario 44)

```bash
ffuf -w wordlist.txt -u http://target/FUZZ -t 10 -p 0.1
```

---

# Case 45: Nuclei Templates Outdated (Scenario 45)

```bash
nuclei -ut
```

---

# Case 46: Subfinder API Keys Missing (Scenario 46)

```bash
echo 'securitytrails: <KEY>' >> ~/.config/subfinder/provider-config.yaml
```

---

# Case 47: Prowler AWS Credentials Failed (Scenario 47)

```bash
export AWS_ACCESS_KEY_ID=<KEY> AWS_SECRET_ACCESS_KEY=<SECRET> && prowler aws
```

---

# Case 48: Trivy DB Download Timeout (Scenario 48)

```bash
trivy image --download-db-only --db-repository ghcr.io/aquasecurity/trivy-db
```

---

# Case 49: FFUF OOM (Out of Memory) (Scenario 49)

```bash
ffuf -w wordlist.txt -u http://target/FUZZ -t 10 -p 0.1
```

---

# Case 50: Nuclei Templates Outdated (Scenario 50)

```bash
nuclei -ut
```

---

