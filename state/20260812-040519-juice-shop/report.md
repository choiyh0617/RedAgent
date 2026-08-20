# Pentest Report: 20260812-040519-juice-shop
## Summary

- 대상: 192.168.56.101
- 진행된 단계: exploitation
- 총 findings: 4


## Exploitation

### 192.168.56.101

- **[성공]** port 3000 - SQL Injection (JSON email, /rest/user/login) (방법: SQLi(sqlmap/json))
  - sqlmap이 확인한 인젝션: OR boolean-based blind - WHERE or HAVING clause (NOT)

