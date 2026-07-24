# 🔌 API Errors — SMP V7

## 401 Unauthorized

JWT token expired (default lifetime: 30 minutes).

```bash
# Re-authenticate
TOKEN=$(curl -s -X POST http://localhost:8000/api/v7/auth/token \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"yourpassword"}' | jq -r .access_token)
echo $TOKEN
```

To extend token lifetime, set in `config/settings.json`:
```json
{ "jwt_expire_minutes": 480 }
```

---

## 403 Forbidden

Your token is valid but lacks permission for this endpoint. Ensure you're using an admin token.

---

## 422 Unprocessable Entity

Request body is malformed. Check the schema at `http://localhost:8000/api/v7/docs`.

Common mistake — target URL must include protocol:
```bash
# Wrong
{"url": "example.com"}

# Correct
{"url": "https://example.com"}
```

---

## 429 Too Many Requests

Built-in rate limiter. Default: 60 requests/minute per IP.

```json
{ "api_rate_limit": 300 }
```

---

## FastAPI won't start: address already in use

```bash
# Find what's on port 8000
lsof -i :8000
kill -9 <PID>

# Or change port
echo '{ "api_port": 8001 }' >> config/settings.json
```

---

## FastAPI import error at startup

```
ImportError: cannot import name 'xyz' from 'tools.db_manager'
```

SQLCipher startup guard triggered — `pysqlcipher3` is not installed. Fix:
```bash
sudo apt install libsqlcipher-dev && pip install pysqlcipher3
```

---

## /api/v7/docs returns 404

The API version in the URL must match the running server version. Check running version:
```bash
curl http://localhost:8000/api/v7/version
# or try /api/v6/version if on an older install
```

---

## CORS error from browser

Add your frontend origin to allowed origins in `config/settings.json`:
```json
{ "cors_origins": ["http://localhost:3000", "https://yourdomain.com"] }
```

---

## JWT secret not set / insecure default

On first run, SMP generates a random JWT secret. If you need to rotate it:
```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
# Add output to config/settings.json:
# { "jwt_secret": "generated_value_here" }
```

---

## Scan trigger returns 409 Conflict

A scan is already running for this target. Check:
```bash
curl http://localhost:8000/api/v7/scan/1/status \
  -H "Authorization: Bearer $TOKEN"
```

Wait for it to complete or cancel it via the GUI.
