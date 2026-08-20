# Pentest Report: 20260813-162620-juice-shop-local
## Summary

- 대상: 127.0.0.1
- 진행된 단계: exploitation, web_agent
- 총 findings: 3


## Exploitation

### 127.0.0.1

- **[성공]** port 3000 - SQL Injection (email, /rest/user/login) (방법: SQLi(local-known-payload))
  - 로컬 직접 검증 성공: ' or 1=1 -- -


## Web Post-Exploitation

### 127.0.0.1

- 테스트 과정:
  - `try_login_bypass(local-known-payload)` (/rest/user/login)
- 최종 결과: **[실패]** 로컬 호스트에서 Juice Shop 로그인 SQLi를 재현했고 관리자 JWT가 응답에 포함된 것까지 확인함. 다만 SPA/JWT 후속 탐색 자동화는 아직 로컬 모드에 맞게 구현되지 않아 여기서 부분 성공으로 종료함.

