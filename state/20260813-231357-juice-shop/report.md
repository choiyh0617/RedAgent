# Pentest Report: 20260813-231357-juice-shop
## Summary

- 대상: 192.168.56.101
- 진행된 단계: exploitation, web_agent
- 총 findings: 11

### 비전문가용 한줄 요약

- 외부 입력을 악용해 로그인 절차를 우회했고, 그 결과 관리자 권한으로 내부 데이터를 조회할 수 있었다.
- 즉, 공격자는 단순한 로그인 실패가 아니라 실제 운영 데이터에 접근 가능한 상태까지 도달했다.

### 이 보고서를 어떻게 읽으면 되는가

- `무엇이 실제로 가능했는가`: 공격자가 어디까지 접근했는지 보여준다.
- `왜 문제인가`: 비보안 담당자 기준으로 사업/운영 관점의 위험을 설명한다.
- `권장 조치`: 개발팀, 운영팀, 보안팀이 바로 실행할 수 있는 후속 대응을 적었다.


## Exploitation

### 192.168.56.101

이 단계에서는 실제로 공격이 재현됐다. 즉, 이론상 취약 가능성이 아니라 외부에서 악용 가능한 경로가 최소 1건 확인된 상태다.

- **[성공]** port 3000 - SQL Injection (email, /rest/user/login) (방법: SQLi(local-known-payload))
  - 근거: 로컬 직접 검증 성공: ' or 1=1 -- -
  - 원인: 사용자 입력이 SQL 질의문에 안전하게 바인딩되지 않아, 입력값이 명령처럼 해석됐다.
  - 영향: 공격자가 비밀번호를 몰라도 로그인 우회, 데이터 조회, 경우에 따라 데이터 변경까지 시도할 수 있다.
  - 보안 권고: Prepared Statement 적용, ORM 파라미터 바인딩 강제, 관리자 기능 쿼리 전수 점검이 필요하다.


## Web Post-Exploitation

### 192.168.56.101

이 섹션은 '공격자가 로그인 우회 이후 실제로 어디까지 볼 수 있었는지'를 비전문가도 이해할 수 있게 풀어쓴 부분이다.

#### 공격 흐름

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

#### 무엇이 실제로 보였는가

1. `try_login_bypass(local-known-payload)`
   - 요약: 로그인 우회가 성공해 인증 토큰이 발급됐다.
   - 접속된 계정: `admin@juice-sh.op`
   - 연결된 장바구니 ID: `1`
   - 의미: 비밀번호를 모르는 상태에서도 정상 사용자처럼 세션을 얻을 수 있었다.
   - 원인: 로그인 요청의 입력값이 안전하게 처리되지 않아 인증 우회가 가능했다.
   - 보안 권고: 로그인 API에 파라미터 바인딩, 실패 로그 분석, 계정 잠금/탐지 정책을 함께 적용해야 한다.
   - 원본 응답 일부: `{"authentication":{"token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJkYXRhIjp7ImlkIjoxLCJ1c2VybmFtZSI6IiIsImVtYWlsIjoiYWRtaW5AanVpY2Utc2gub3AiLCJwYXNzd29yZCI6IjAxOTIwMjNhN2JiZDczMjUwNTE2ZjA2OWRmMThiNTAwIiwicm9sZSI6ImFkbWl...`

2. `list_users`
   - 요약: 사용자 목록 조회에 성공했다. 총 22개 계정 중 관리자 권한 계정이 7개 확인됐다.
   - 노출 예시: `admin@juice-sh.op`, `jim@juice-sh.op`, `bender@juice-sh.op`, `bjoern.kimminich@gmail.com`, `ciso@juice-sh.op`
   - 의미: 공격자가 가입자 현황과 관리자 계정을 식별해 추가 공격 대상을 고를 수 있다.
   - 원인: 관리자 전용 사용자 조회 API가 우회된 세션 또는 부적절한 권한으로도 접근 가능했다.
   - 보안 권고: 서버 측 인가 검사를 강화하고, 관리자 전용 엔드포인트를 일반 세션과 분리해야 한다.
   - 원본 응답 일부: `{"status":"success","data":[{"id":1,"username":"","email":"admin@juice-sh.op","role":"admin","deluxeToken":"","lastLoginIp":"","profileImage":"assets/public/images/uploads/defaultAdmin.png","isActive":true,"createdAt":"2...`

3. `application_version`
   - 요약: 관리자 전용 애플리케이션 정보 조회에 성공했다.
   - 확인된 버전: `20.1.1`
   - 의미: 공격자는 서버 버전을 바탕으로 알려진 취약점을 추가로 탐색할 수 있다.
   - 원인: 내부 운영 정보가 불필요하게 외부 응답으로 노출됐다.
   - 보안 권고: 상세 버전 정보는 관리자 콘솔이나 내부 로그로 제한하고 외부 응답에서는 제거하는 것이 좋다.
   - 원본 응답 일부: `{"version":"20.1.1"}`

4. `basket_items`
   - 요약: 장바구니 데이터 조회에 성공했다. 총 8개 항목이 5개 장바구니에 걸쳐 노출됐다.
   - 노출 예시: 장바구니 `1`: 상품ID 1 x2, 상품ID 2 x3, 상품ID 3 x1 / 장바구니 `2`: 상품ID 4 x2 / 장바구니 `3`: 상품ID 4 x1
   - 의미: 어떤 사용자가 무엇을 담았는지 추정할 수 있어 구매 의도와 이용 행태가 노출된다.
   - 원인: 장바구니 조회가 사용자 소유권 검증 없이 가능했거나 관리자 세션 보호가 약했다.
   - 보안 권고: 객체 수준 접근통제(BOLA/IDOR 방지)를 적용해 본인 데이터만 조회되도록 강제해야 한다.
   - 원본 응답 일부: `{"status":"success","data":[{"ProductId":1,"BasketId":1,"id":1,"quantity":2,"createdAt":"2026-08-13T03:43:16.182Z","updatedAt":"2026-08-13T03:43:16.182Z"},{"ProductId":2,"BasketId":1,"id":2,"quantity":3,"createdAt":"2026...`

#### 최종 판단

- 상태: **[성공]**
- 판단: 로컬 Juice Shop에서 로그인 SQLi로 관리자 JWT를 획득했고, 인증된 관리자 API 접근까지 확인했다.
- 쉬운 설명: 인증 장벽을 우회한 뒤, 일반 사용자에게 보이면 안 되는 관리자급 정보까지 실제로 열람 가능했다.
- 확인된 항목:
  - `list_users` / `/api/Users` / confirmed
  - `application_version` / `/rest/admin/application-version` / confirmed
  - `basket_items` / `/api/BasketItems/` / confirmed
- 왜 문제인가:
  - 인증 우회가 가능하다는 것은 '로그인 화면이 사실상 보안 장치 역할을 못 했다'는 뜻이다.
  - 사용자 목록이 보이면 계정 수집, 관리자 식별, 피싱 또는 비밀번호 재사용 공격으로 이어질 수 있다.
  - 장바구니 정보는 결제 전 행동 데이터라서 개인정보와 상거래 정보 유출로 해석할 수 있다.
  - 버전 정보는 공격자에게 다음 공격을 위한 안내서 역할을 한다.
- 권장 조치:
  1. 로그인 API의 입력값 검증을 강화하고, 문자열 결합 쿼리를 중단한 뒤 파라미터 바인딩(Prepared Statement)으로 전면 교체한다.
  2. 인증과 인가를 분리해 점검한다. 로그인에 성공했더라도 관리자 API는 서버 측 권한 검증을 다시 수행해야 한다.
  3. 관리자 API(`/api/Users`, `/rest/admin/*`)는 최소권한 원칙으로 재설계하고, 일반 사용자 토큰으로는 접근이 불가능해야 한다.
  4. 장바구니·주문 데이터 API는 본인 소유 데이터만 반환하도록 객체 수준 접근통제(BOLA/IDOR 방지)를 점검한다.
  5. 이번에 노출된 토큰·세션·관리자 계정은 모두 무효화하고, 동일 패턴의 우회 시도가 있었는지 서버 로그를 점검한다.
  6. 재발 방지를 위해 로그인, 관리자 API, 핵심 조회 API를 포함한 회귀 테스트를 추가한다.
- 로그인 우회 응답 일부: `{"authentication":{"token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJkYXRhIjp7ImlkIjoxLCJ1c2VybmFtZSI6IiIsImVtYWlsIjoiYWRtaW5AanVpY2Utc2gub3AiLCJwYXNzd29yZCI6IjAxOTIwMjNhN2JiZDczMjUwNTE2ZjA2OWRmMThiNTAwIiwicm9sZSI6ImFkbWl...`

