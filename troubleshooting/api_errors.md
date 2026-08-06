# 🔌 API Errors — SMP V9.3.3

## 401 Unauthorized

JWT token expired (default lifetime: 30 minutes).

```bash
# Re-authenticate
TOKEN=$(curl -s -X POST http://localhost:8000/api/v9.3.3/auth/token \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"yourpassword"}' | jq -r .access_token)
echo $TOKEN
```

To extend token lifetime, set in `config/settings.json`:
```bash
python3 -c "import json, os; p='config/settings.json'; d=json.load(open(p)) if os.path.exists(p) else {}; d['jwt_expire_minutes']=480; json.dump(d, open(p,'w'), indent=4)"
```

---

## 403 Forbidden

Your token is valid but lacks permission for this endpoint. Ensure you're using an admin token.

---

## 422 Unprocessable Entity

Request body is malformed. Check the schema at `http://localhost:8000/api/v9.3.3/docs`.

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

```bash
python3 -c "import json, os; p='config/settings.json'; d=json.load(open(p)) if os.path.exists(p) else {}; d['api_rate_limit']=300; json.dump(d, open(p,'w'), indent=4)"
```

---

## FastAPI won't start: address already in use

```bash
# Find what's on port 8000
lsof -i :8000
kill -9 <PID>

# Or change port
python3 -c "import json, os; p='config/settings.json'; d=json.load(open(p)) if os.path.exists(p) else {}; d['api_port']=8001; json.dump(d, open(p,'w'), indent=4)"
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

## /api/v9.3.3/docs returns 404

The API version in the URL must match the running server version. Check running version:
```bash
curl http://localhost:8000/api/v9.3.3/version
# or try /api/v6/version if on an older install
```

---

## CORS error from browser

Add your frontend origin to allowed origins in `config/settings.json`:
```bash
python3 -c "import json, os; p='config/settings.json'; d=json.load(open(p)) if os.path.exists(p) else {}; d['cors_origins']=['http://localhost:3000', 'https://yourdomain.com']; json.dump(d, open(p,'w'), indent=4)"
```

---

## JWT secret not set / insecure default

On first run, SMP generates a random JWT secret. If you need to rotate it:
```bash
python3 -c "import secrets, json, os; p='config/settings.json'; d=json.load(open(p)) if os.path.exists(p) else {}; d['jwt_secret']=secrets.token_hex(32); json.dump(d, open(p,'w'), indent=4)"
```

---

## Scan trigger returns 409 Conflict

A scan is already running for this target. Check:
```bash
curl http://localhost:8000/api/v9.3.3/scan/1/status \
  -H "Authorization: Bearer $TOKEN"
```

Wait for it to complete or cancel it via the GUI.
