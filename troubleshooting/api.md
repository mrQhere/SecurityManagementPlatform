# Api Troubleshooting

This document contains 50 distinct troubleshooting cases.

## General Diagnostics
The system encountered an issue related to this category. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

**Copy-Paste Solutions:** Run the respective command in your terminal to instantly resolve the issue. *(Note: Ensure you have the appropriate permissions before executing administrative commands.)*

---

# Case 1: JWT Token Expired (Scenario 1)

```bash
curl -X POST http://localhost:8000/api/v6/auth/token -u admin:<PASSWORD>
```

---

# Case 2: CORS Preflight Failure (Scenario 2)

```bash
export SMP_CORS_ORIGINS='*' && systemctl restart smp-api
```

---

# Case 3: 502 Bad Gateway (Scenario 3)

```bash
systemctl restart smp-api && journalctl -u smp-api -f
```

---

# Case 4: SSL Certificate Expired (Scenario 4)

```bash
certbot renew --force-renewal && systemctl restart nginx
```

---

# Case 5: Rate Limit Exceeded (IP Block) (Scenario 5)

```bash
curl -X POST http://localhost:8000/api/v6/admin/unban -d '{"ip": "192.168.1.50"}' -H 'Authorization: Bearer <TOKEN>'
```

---

# Case 6: JWT Token Expired (Scenario 6)

```bash
curl -X POST http://localhost:8000/api/v6/auth/token -u admin:<PASSWORD>
```

---

# Case 7: CORS Preflight Failure (Scenario 7)

```bash
export SMP_CORS_ORIGINS='*' && systemctl restart smp-api
```

---

# Case 8: 502 Bad Gateway (Scenario 8)

```bash
systemctl restart smp-api && journalctl -u smp-api -f
```

---

# Case 9: SSL Certificate Expired (Scenario 9)

```bash
certbot renew --force-renewal && systemctl restart nginx
```

---

# Case 10: Rate Limit Exceeded (IP Block) (Scenario 10)

```bash
curl -X POST http://localhost:8000/api/v6/admin/unban -d '{"ip": "10.0.0.10"}' -H 'Authorization: Bearer <TOKEN>'
```

---

# Case 11: JWT Token Expired (Scenario 11)

```bash
curl -X POST http://localhost:8000/api/v6/auth/token -u admin:<PASSWORD>
```

---

# Case 12: CORS Preflight Failure (Scenario 12)

```bash
export SMP_CORS_ORIGINS='*' && systemctl restart smp-api
```

---

# Case 13: 502 Bad Gateway (Scenario 13)

```bash
systemctl restart smp-api && journalctl -u smp-api -f
```

---

# Case 14: SSL Certificate Expired (Scenario 14)

```bash
certbot renew --force-renewal && systemctl restart nginx
```

---

# Case 15: Rate Limit Exceeded (IP Block) (Scenario 15)

```bash
curl -X POST http://localhost:8000/api/v6/admin/unban -d '{"ip": "10.0.0.15"}' -H 'Authorization: Bearer <TOKEN>'
```

---

# Case 16: JWT Token Expired (Scenario 16)

```bash
curl -X POST http://localhost:8000/api/v6/auth/token -u admin:<PASSWORD>
```

---

# Case 17: CORS Preflight Failure (Scenario 17)

```bash
export SMP_CORS_ORIGINS='*' && systemctl restart smp-api
```

---

# Case 18: 502 Bad Gateway (Scenario 18)

```bash
systemctl restart smp-api && journalctl -u smp-api -f
```

---

# Case 19: SSL Certificate Expired (Scenario 19)

```bash
certbot renew --force-renewal && systemctl restart nginx
```

---

# Case 20: Rate Limit Exceeded (IP Block) (Scenario 20)

```bash
curl -X POST http://localhost:8000/api/v6/admin/unban -d '{"ip": "10.0.0.20"}' -H 'Authorization: Bearer <TOKEN>'
```

---

# Case 21: JWT Token Expired (Scenario 21)

```bash
curl -X POST http://localhost:8000/api/v6/auth/token -u admin:<PASSWORD>
```

---

# Case 22: CORS Preflight Failure (Scenario 22)

```bash
export SMP_CORS_ORIGINS='*' && systemctl restart smp-api
```

---

# Case 23: 502 Bad Gateway (Scenario 23)

```bash
systemctl restart smp-api && journalctl -u smp-api -f
```

---

# Case 24: SSL Certificate Expired (Scenario 24)

```bash
certbot renew --force-renewal && systemctl restart nginx
```

---

# Case 25: Rate Limit Exceeded (IP Block) (Scenario 25)

```bash
curl -X POST http://localhost:8000/api/v6/admin/unban -d '{"ip": "10.0.0.25"}' -H 'Authorization: Bearer <TOKEN>'
```

---

# Case 26: JWT Token Expired (Scenario 26)

```bash
curl -X POST http://localhost:8000/api/v6/auth/token -u admin:<PASSWORD>
```

---

# Case 27: CORS Preflight Failure (Scenario 27)

```bash
export SMP_CORS_ORIGINS='*' && systemctl restart smp-api
```

---

# Case 28: 502 Bad Gateway (Scenario 28)

```bash
systemctl restart smp-api && journalctl -u smp-api -f
```

---

# Case 29: SSL Certificate Expired (Scenario 29)

```bash
certbot renew --force-renewal && systemctl restart nginx
```

---

# Case 30: Rate Limit Exceeded (IP Block) (Scenario 30)

```bash
curl -X POST http://localhost:8000/api/v6/admin/unban -d '{"ip": "10.0.0.30"}' -H 'Authorization: Bearer <TOKEN>'
```

---

# Case 31: JWT Token Expired (Scenario 31)

```bash
curl -X POST http://localhost:8000/api/v6/auth/token -u admin:<PASSWORD>
```

---

# Case 32: CORS Preflight Failure (Scenario 32)

```bash
export SMP_CORS_ORIGINS='*' && systemctl restart smp-api
```

---

# Case 33: 502 Bad Gateway (Scenario 33)

```bash
systemctl restart smp-api && journalctl -u smp-api -f
```

---

# Case 34: SSL Certificate Expired (Scenario 34)

```bash
certbot renew --force-renewal && systemctl restart nginx
```

---

# Case 35: Rate Limit Exceeded (IP Block) (Scenario 35)

```bash
curl -X POST http://localhost:8000/api/v6/admin/unban -d '{"ip": "10.0.0.35"}' -H 'Authorization: Bearer <TOKEN>'
```

---

# Case 36: JWT Token Expired (Scenario 36)

```bash
curl -X POST http://localhost:8000/api/v6/auth/token -u admin:<PASSWORD>
```

---

# Case 37: CORS Preflight Failure (Scenario 37)

```bash
export SMP_CORS_ORIGINS='*' && systemctl restart smp-api
```

---

# Case 38: 502 Bad Gateway (Scenario 38)

```bash
systemctl restart smp-api && journalctl -u smp-api -f
```

---

# Case 39: SSL Certificate Expired (Scenario 39)

```bash
certbot renew --force-renewal && systemctl restart nginx
```

---

# Case 40: Rate Limit Exceeded (IP Block) (Scenario 40)

```bash
curl -X POST http://localhost:8000/api/v6/admin/unban -d '{"ip": "10.0.0.40"}' -H 'Authorization: Bearer <TOKEN>'
```

---

# Case 41: JWT Token Expired (Scenario 41)

```bash
curl -X POST http://localhost:8000/api/v6/auth/token -u admin:<PASSWORD>
```

---

# Case 42: CORS Preflight Failure (Scenario 42)

```bash
export SMP_CORS_ORIGINS='*' && systemctl restart smp-api
```

---

# Case 43: 502 Bad Gateway (Scenario 43)

```bash
systemctl restart smp-api && journalctl -u smp-api -f
```

---

# Case 44: SSL Certificate Expired (Scenario 44)

```bash
certbot renew --force-renewal && systemctl restart nginx
```

---

# Case 45: Rate Limit Exceeded (IP Block) (Scenario 45)

```bash
curl -X POST http://localhost:8000/api/v6/admin/unban -d '{"ip": "10.0.0.45"}' -H 'Authorization: Bearer <TOKEN>'
```

---

# Case 46: JWT Token Expired (Scenario 46)

```bash
curl -X POST http://localhost:8000/api/v6/auth/token -u admin:<PASSWORD>
```

---

# Case 47: CORS Preflight Failure (Scenario 47)

```bash
export SMP_CORS_ORIGINS='*' && systemctl restart smp-api
```

---

# Case 48: 502 Bad Gateway (Scenario 48)

```bash
systemctl restart smp-api && journalctl -u smp-api -f
```

---

# Case 49: SSL Certificate Expired (Scenario 49)

```bash
certbot renew --force-renewal && systemctl restart nginx
```

---

# Case 50: Rate Limit Exceeded (IP Block) (Scenario 50)

```bash
curl -X POST http://localhost:8000/api/v6/admin/unban -d '{"ip": "10.0.0.50"}' -H 'Authorization: Bearer <TOKEN>'
```

---

