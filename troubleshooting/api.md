# 🔌 API & Authentication Troubleshooting — V9.5

This guide provides technical diagnosis and copy-paste remediation procedures for the SMP FastAPI backend, JWT authentication, rate limiting, and WebSocket telemetry stream.

---

## Error Codes Covered

| Code | Slug | Issue Description |
|---|---|---|
| `SMP-1000` | `auth_error` | Generic authentication failure / missing Authorization header |
| `SMP-1001` | `token_expired` | JWT bearer token expired |
| `SMP-1002` | `invalid_credentials` | Master password or login credentials rejected |
| `SMP-1003` | `password_policy_violation` | Master password does not satisfy complexity policy |
| `SMP-1005` | `dek_unavailable` | Database Encryption Key not loaded (application locked) |
| `SMP-4000` | `validation_error` | Generic request body validation failure |
| `SMP-4001` | `invalid_target` | Malformed target URL, IP, or hostname |
| `SMP-4002` | `invalid_payload` | Unparseable or malformed JSON payload |
| `SMP-6000` | `scope_violation` | Target out of authorized engagement scope |
| `SMP-6006` | `responsibility_attestation_missing` | Operator authorization attestation missing |

---

## Common Scenarios & Resolutions

### Scenario 1: JWT Bearer Token Expired (`SMP-1001`)

**Symptom:** API requests return `401 Unauthorized` with payload `{"code": "SMP-1001", "slug": "token_expired"}`.

**Root Cause:** The Bearer JWT token lifetime (default 24 hours) has elapsed.

**Copy-Paste Solution:**
```bash
# Obtain a fresh Bearer token using your master password
TOKEN=$(curl -s -X POST http://localhost:8000/api/v6/auth/token \
 -H "Content-Type: application/json" \
 -d '{"password": "YOUR_MASTER_PASSWORD"}' | jq -r .access_token)

# Verify token by calling system status
curl -s http://localhost:8000/api/v6/system/status \
 -H "Authorization: Bearer $TOKEN" | jq .
```

---

### Scenario 2: Rate Limit Exceeded (`HTTP 429 Too Many Requests`)

**Symptom:** High-frequency API calls return `HTTP 429` with `RateLimitExceeded`.

**Root Cause:** SlowAPI limiter triggered due to exceeding the default rate ceiling (100 requests/minute per client IP).

**Copy-Paste Solution:**
```bash
# Option A: Adjust rate limit via environment variable and restart API
export SMP_RATE_LIMIT="500/minute"
python3 main.py --api

# Option B: Whitelist client IP in config/settings.json
jq '.api.rate_limit_whitelist += ["192.168.1.50", "127.0.0.1"]' config/settings.json > config/settings.tmp \
 && mv config/settings.tmp config/settings.json
```

---

### Scenario 3: Database Locked / DEK Unavailable (`SMP-1005`)

**Symptom:** Endpoint returns `500 Internal Server Error` with `{"code": "SMP-1005", "slug": "dek_unavailable"}`.

**Root Cause:** API backend was started in headless mode without supplying the master password to derive the Database Encryption Key (DEK).

**Copy-Paste Solution:**
```bash
# Authenticate and unlock the in-memory KeyStore
curl -X POST http://localhost:8000/api/v6/auth/unlock \
 -H "Content-Type: application/json" \
 -d '{"master_password": "YOUR_MASTER_PASSWORD"}'
```

---

### Scenario 4: Target URL Rejected (`SMP-4001`)

**Symptom:** Target creation fails with `{"code": "SMP-4001", "message": "URL must start with http:// or https://"}`.

**Root Cause:** Target string lacks protocol scheme or contains invalid URI characters.

**Copy-Paste Solution:**
```bash
# Correct format: Always include scheme and valid host
curl -X POST http://localhost:8000/api/v6/targets \
 -H "Authorization: Bearer $TOKEN" \
 -H "Content-Type: application/json" \
 -d '{
 "target": "https://target-organization.internal",
 "company_name": "Target Org",
 "submitted_to": "Security Operations Team"
 }'
```

---

### Scenario 5: Missing Responsibility Attestation (`SMP-6006`)

**Symptom:** Scan initiation returns `400 Bad Request` with `{"code": "SMP-6006", "slug": "responsibility_attestation_missing"}`.

**Root Cause:** Active/intrusive testing was requested without operator attestation of written testing authorization.

**Copy-Paste Solution:**
```bash
# Pass attestation=true in the scan launch payload
curl -X POST http://localhost:8000/api/v6/scans \
 -H "Authorization: Bearer $TOKEN" \
 -H "Content-Type: application/json" \
 -d '{
 "target_id": 1,
 "scan_type": "standard",
 "attestation": true
 }'
```

---

### Scenario 6: CORS Preflight Failure on Custom Frontend

**Symptom:** Browser console reports: `Access to XMLHttpRequest at 'http://localhost:8000' from origin 'http://localhost:3000' has been blocked by CORS policy`.

**Root Cause:** The frontend web origin is not in the FastAPI CORS `allow_origins` list.

**Copy-Paste Solution:**
```bash
# Export allowed origins environment variable before launching API
export SMP_CORS_ORIGINS="http://localhost:3000,http://127.0.0.1:3000,https://smp.internal"
python3 main.py --api
```

---

### Scenario 7: WebSocket Telemetry Stream Drops Behind Reverse Proxy

**Symptom:** Real-time scan logs in dashboard disconnect after exactly 60 seconds.

**Root Cause:** Nginx reverse proxy closing inactive WebSocket connections due to missing proxy headers.

**Copy-Paste Solution:**
Add WebSocket upgrade directives to `/etc/nginx/sites-available/smp`:

```nginx
location /api/v6/ws/ {
 proxy_pass http://127.0.0.1:8000;
 proxy_http_version 1.1;
 proxy_set_header Upgrade $http_upgrade;
 proxy_set_header Connection "upgrade";
 proxy_set_header Host $host;
 proxy_read_timeout 86400s;
 proxy_send_timeout 86400s;
}
```
```bash
sudo nginx -t && sudo systemctl reload nginx
```

---

### Scenario 8: Port 8000 Collision on API Startup

**Symptom:** `main.py --api` fails with `[Errno 98] Address already in use`.

**Root Cause:** An existing Uvicorn process or another local web service is occupying port 8000.

**Copy-Paste Solution:**
```bash
# Find and terminate the process holding port 8000
sudo fuser -k 8000/tcp

# Or start SMP API on an alternative port
python3 main.py --api --port 8080
```
