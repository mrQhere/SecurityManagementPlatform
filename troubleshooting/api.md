# Api Troubleshooting

This document contains 50 distinct troubleshooting cases.

---

# Case 1: JWT Token Expired (Scenario 1)

## Problem Description
The system encountered an issue related to api. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
curl -X POST http://localhost:8000/api/v6/auth/token -u admin:<PASSWORD>
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 2: CORS Preflight Failure (Scenario 2)

## Problem Description
The system encountered an issue related to api. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
export SMP_CORS_ORIGINS='*' && systemctl restart smp-api
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 3: 502 Bad Gateway (Scenario 3)

## Problem Description
The system encountered an issue related to api. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
systemctl restart smp-api && journalctl -u smp-api -f
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 4: SSL Certificate Expired (Scenario 4)

## Problem Description
The system encountered an issue related to api. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
certbot renew --force-renewal && systemctl restart nginx
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 5: Rate Limit Exceeded (IP Block) (Scenario 5)

## Problem Description
The system encountered an issue related to api. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
curl -X POST http://localhost:8000/api/v6/admin/unban -d '{"ip": "192.168.1.50"}' -H 'Authorization: Bearer <TOKEN>'
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 6: JWT Token Expired (Scenario 6)

## Problem Description
The system encountered an issue related to api. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
curl -X POST http://localhost:8000/api/v6/auth/token -u admin:<PASSWORD>
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 7: CORS Preflight Failure (Scenario 7)

## Problem Description
The system encountered an issue related to api. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
export SMP_CORS_ORIGINS='*' && systemctl restart smp-api
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 8: 502 Bad Gateway (Scenario 8)

## Problem Description
The system encountered an issue related to api. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
systemctl restart smp-api && journalctl -u smp-api -f
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 9: SSL Certificate Expired (Scenario 9)

## Problem Description
The system encountered an issue related to api. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
certbot renew --force-renewal && systemctl restart nginx
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 10: Rate Limit Exceeded (IP Block) (Scenario 10)

## Problem Description
The system encountered an issue related to api. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
curl -X POST http://localhost:8000/api/v6/admin/unban -d '{"ip": "10.0.0.10"}' -H 'Authorization: Bearer <TOKEN>'
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 11: JWT Token Expired (Scenario 11)

## Problem Description
The system encountered an issue related to api. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
curl -X POST http://localhost:8000/api/v6/auth/token -u admin:<PASSWORD>
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 12: CORS Preflight Failure (Scenario 12)

## Problem Description
The system encountered an issue related to api. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
export SMP_CORS_ORIGINS='*' && systemctl restart smp-api
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 13: 502 Bad Gateway (Scenario 13)

## Problem Description
The system encountered an issue related to api. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
systemctl restart smp-api && journalctl -u smp-api -f
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 14: SSL Certificate Expired (Scenario 14)

## Problem Description
The system encountered an issue related to api. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
certbot renew --force-renewal && systemctl restart nginx
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 15: Rate Limit Exceeded (IP Block) (Scenario 15)

## Problem Description
The system encountered an issue related to api. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
curl -X POST http://localhost:8000/api/v6/admin/unban -d '{"ip": "10.0.0.15"}' -H 'Authorization: Bearer <TOKEN>'
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 16: JWT Token Expired (Scenario 16)

## Problem Description
The system encountered an issue related to api. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
curl -X POST http://localhost:8000/api/v6/auth/token -u admin:<PASSWORD>
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 17: CORS Preflight Failure (Scenario 17)

## Problem Description
The system encountered an issue related to api. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
export SMP_CORS_ORIGINS='*' && systemctl restart smp-api
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 18: 502 Bad Gateway (Scenario 18)

## Problem Description
The system encountered an issue related to api. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
systemctl restart smp-api && journalctl -u smp-api -f
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 19: SSL Certificate Expired (Scenario 19)

## Problem Description
The system encountered an issue related to api. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
certbot renew --force-renewal && systemctl restart nginx
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 20: Rate Limit Exceeded (IP Block) (Scenario 20)

## Problem Description
The system encountered an issue related to api. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
curl -X POST http://localhost:8000/api/v6/admin/unban -d '{"ip": "10.0.0.20"}' -H 'Authorization: Bearer <TOKEN>'
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 21: JWT Token Expired (Scenario 21)

## Problem Description
The system encountered an issue related to api. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
curl -X POST http://localhost:8000/api/v6/auth/token -u admin:<PASSWORD>
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 22: CORS Preflight Failure (Scenario 22)

## Problem Description
The system encountered an issue related to api. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
export SMP_CORS_ORIGINS='*' && systemctl restart smp-api
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 23: 502 Bad Gateway (Scenario 23)

## Problem Description
The system encountered an issue related to api. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
systemctl restart smp-api && journalctl -u smp-api -f
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 24: SSL Certificate Expired (Scenario 24)

## Problem Description
The system encountered an issue related to api. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
certbot renew --force-renewal && systemctl restart nginx
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 25: Rate Limit Exceeded (IP Block) (Scenario 25)

## Problem Description
The system encountered an issue related to api. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
curl -X POST http://localhost:8000/api/v6/admin/unban -d '{"ip": "10.0.0.25"}' -H 'Authorization: Bearer <TOKEN>'
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 26: JWT Token Expired (Scenario 26)

## Problem Description
The system encountered an issue related to api. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
curl -X POST http://localhost:8000/api/v6/auth/token -u admin:<PASSWORD>
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 27: CORS Preflight Failure (Scenario 27)

## Problem Description
The system encountered an issue related to api. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
export SMP_CORS_ORIGINS='*' && systemctl restart smp-api
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 28: 502 Bad Gateway (Scenario 28)

## Problem Description
The system encountered an issue related to api. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
systemctl restart smp-api && journalctl -u smp-api -f
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 29: SSL Certificate Expired (Scenario 29)

## Problem Description
The system encountered an issue related to api. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
certbot renew --force-renewal && systemctl restart nginx
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 30: Rate Limit Exceeded (IP Block) (Scenario 30)

## Problem Description
The system encountered an issue related to api. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
curl -X POST http://localhost:8000/api/v6/admin/unban -d '{"ip": "10.0.0.30"}' -H 'Authorization: Bearer <TOKEN>'
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 31: JWT Token Expired (Scenario 31)

## Problem Description
The system encountered an issue related to api. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
curl -X POST http://localhost:8000/api/v6/auth/token -u admin:<PASSWORD>
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 32: CORS Preflight Failure (Scenario 32)

## Problem Description
The system encountered an issue related to api. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
export SMP_CORS_ORIGINS='*' && systemctl restart smp-api
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 33: 502 Bad Gateway (Scenario 33)

## Problem Description
The system encountered an issue related to api. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
systemctl restart smp-api && journalctl -u smp-api -f
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 34: SSL Certificate Expired (Scenario 34)

## Problem Description
The system encountered an issue related to api. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
certbot renew --force-renewal && systemctl restart nginx
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 35: Rate Limit Exceeded (IP Block) (Scenario 35)

## Problem Description
The system encountered an issue related to api. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
curl -X POST http://localhost:8000/api/v6/admin/unban -d '{"ip": "10.0.0.35"}' -H 'Authorization: Bearer <TOKEN>'
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 36: JWT Token Expired (Scenario 36)

## Problem Description
The system encountered an issue related to api. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
curl -X POST http://localhost:8000/api/v6/auth/token -u admin:<PASSWORD>
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 37: CORS Preflight Failure (Scenario 37)

## Problem Description
The system encountered an issue related to api. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
export SMP_CORS_ORIGINS='*' && systemctl restart smp-api
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 38: 502 Bad Gateway (Scenario 38)

## Problem Description
The system encountered an issue related to api. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
systemctl restart smp-api && journalctl -u smp-api -f
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 39: SSL Certificate Expired (Scenario 39)

## Problem Description
The system encountered an issue related to api. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
certbot renew --force-renewal && systemctl restart nginx
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 40: Rate Limit Exceeded (IP Block) (Scenario 40)

## Problem Description
The system encountered an issue related to api. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
curl -X POST http://localhost:8000/api/v6/admin/unban -d '{"ip": "10.0.0.40"}' -H 'Authorization: Bearer <TOKEN>'
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 41: JWT Token Expired (Scenario 41)

## Problem Description
The system encountered an issue related to api. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
curl -X POST http://localhost:8000/api/v6/auth/token -u admin:<PASSWORD>
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 42: CORS Preflight Failure (Scenario 42)

## Problem Description
The system encountered an issue related to api. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
export SMP_CORS_ORIGINS='*' && systemctl restart smp-api
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 43: 502 Bad Gateway (Scenario 43)

## Problem Description
The system encountered an issue related to api. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
systemctl restart smp-api && journalctl -u smp-api -f
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 44: SSL Certificate Expired (Scenario 44)

## Problem Description
The system encountered an issue related to api. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
certbot renew --force-renewal && systemctl restart nginx
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 45: Rate Limit Exceeded (IP Block) (Scenario 45)

## Problem Description
The system encountered an issue related to api. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
curl -X POST http://localhost:8000/api/v6/admin/unban -d '{"ip": "10.0.0.45"}' -H 'Authorization: Bearer <TOKEN>'
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 46: JWT Token Expired (Scenario 46)

## Problem Description
The system encountered an issue related to api. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
curl -X POST http://localhost:8000/api/v6/auth/token -u admin:<PASSWORD>
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 47: CORS Preflight Failure (Scenario 47)

## Problem Description
The system encountered an issue related to api. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
export SMP_CORS_ORIGINS='*' && systemctl restart smp-api
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 48: 502 Bad Gateway (Scenario 48)

## Problem Description
The system encountered an issue related to api. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
systemctl restart smp-api && journalctl -u smp-api -f
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 49: SSL Certificate Expired (Scenario 49)

## Problem Description
The system encountered an issue related to api. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
certbot renew --force-renewal && systemctl restart nginx
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


# Case 50: Rate Limit Exceeded (IP Block) (Scenario 50)

## Problem Description
The system encountered an issue related to api. This typically occurs when the configuration is invalid, resources are exhausted, or an external dependency fails.

## Copy-Paste Solution
Run the following command in your terminal to instantly resolve the issue:

```bash
curl -X POST http://localhost:8000/api/v6/admin/unban -d '{"ip": "10.0.0.50"}' -H 'Authorization: Bearer <TOKEN>'
```

---
*Note: Ensure you have the appropriate permissions before executing administrative commands.*


