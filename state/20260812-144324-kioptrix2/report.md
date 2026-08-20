# Pentest Report: 20260812-144324-kioptrix2
## Summary

- 대상: 192.168.56.104
- 진행된 단계: exploitation, scanning, vuln_analysis
- 총 findings: 76


## Scanning

### 192.168.56.104
- 플랫폼 추정: `linux`

| Port | Service | Banner |
|---|---|---|
| 22 | ssh | OpenSSH 3.9p1 (protocol 1.99) |
| 80 | http | Apache httpd 2.0.52 ((CentOS)) |
| 111 | rpcbind | 2 (RPC #100000) |
| 443 | ssl/http | Apache httpd 2.0.52 ((CentOS)) |
| 631 | ipp | CUPS 1.1 |
| 833 | rpcbind |  |
| 3306 | mysql | MySQL (unauthorized) |
- `http_enum` 결과: {'whatweb': '', 'gobuster': ''}
- `http_enum` 결과: {'whatweb': '', 'gobuster': ''}


## Vulnerability Analysis

### 192.168.56.104

- **port 80 (http)** - confidence 0.75, risk `medium` - PoC는 IP만 인자로 받는 순수 소켓 스크립트로 오프셋/쉘코드/버전 문자열 매칭이 필요 없고, CVE-2004-0942는 '2.0.52 이하'로 배너와 정확히 일치해 코드 수정 없이 그대로 실행될 가능성이 높다. 다만 이는 CPU 소모형 DoS(RCE 아님)이므로 실제 영향은 서비스 가용성 저하/행(hang)에 국한되고, trys 값 조정에 따라 성공 여부가 갈릴 수 있어 confidence를 1.0으로 주지 않았다. risk는 서비스 중단을 유발할 수 있어 medium으로 평가한다.
- **port 22 (ssh)** - confidence 0.65, risk `low` - CVE-2018-15473 대상 범위(OpenSSH 2.3~7.7)에 배너의 3.9p1이 포함되므로 버전 조건은 충족하고, PoC는 대상 IP·포트·사용자명만 인자로 받는 구조라 코드 수정 없이 실행 가능한 형태다. 다만 스크립트가 Python2 문법(print문)과 paramiko의 내부 프라이빗 API(_handler_table, MSG_SERVICE_ACCEPT 등)에 강하게 의존해 최신 paramiko/Python 환경에서는 내부 구조 변경으로 실행 자체가 깨질 수 있어 '그대로 통함'을 완전히 보장하긴 어렵다. 성공해도 사용자명 존재 여부만 노출되는 정보수집용 취약점(CVSS 5.3, C:L/I:N/A:N)이라 위험도는 낮다.
- **port 443 (ssl/http)** - confidence 0.25, risk `medium` - 배너 버전(Apache 2.0.52)이 CVE-2004-0942 취약 범위(2.0.52 이하)와 정확히 일치하지만, PoC는 IO::Socket::INET으로 PeerPort=>80에 평문 TCP만 연결하고 SSL/TLS 핸드셋이크를 전혀 수행하지 않는다. 대상은 ssl/http(443)이므로 포트를 443으로 바꾸고 IO::Socket::SSL(또는 동등한 TLS 래핑)로 교체하지 않으면 연결 단계부터 실패해 자동 실행으로는 통하지 않는다. 성공하더라도 CPU 소모형 DoS(CVSS 5.0, C:N/I:N/A:P)로 데이터 유출·RCE는 없고 서비스 가용성 저하에 그쳐 위험도는 medium으로 평가한다.
- **port 833 (rpcbind)** - confidence 0.25, risk `medium` - PoC(26887.rb)는 목적지 포트를 111로 하드코딩(`s.send(pkt, 0, ARGV[0], 111)`)하고 있어 대상이 833번 포트에서 rpcbind를 서비스하는 경우 인자로 IP만 주면 엉뚱한 포트(111)로 패킷이 가서 실패한다 — 최소한 포트 값을 833으로 바꾸는 코드 수정이 필요하다. 또한 이 CVE-2013-1950은 libtirpc 0.2.3 이하의 특정 버전에서만 유효한 취약점이라 대상 rpcbind/libtirpc 버전이 일치하는지 배너만으로는 확인이 안 되어 성공 여부가 불확실하다. 성공하더라도 결과는 RCE가 아닌 서비스 크래시(DoS)에 그쳐 영향 범위가 제한적이다.
- **port 631 (ipp)** - confidence 0.15, risk `high` - 24977.txt은 실제 동작하는 익스플로잇 스크립트가 아니라 취약점 설명 텍스트(advisory)일 뿐이며, hpgltops의 ParseCommand 버퍼오버플로우를 실제로 코드실행으로 연결하려면 공격자가 shellcode/오프셋을 직접 만든 악성 HPGL 페이로드를 작성해야 하고, 이를 IPP로 인쇄 작업 제출해 트리거해야 하므로 'IP만 주면 실행'되는 형태가 아니다. 또한 원 취약점은 CUPS 1.1.22 특정 빌드 기준이라 배너의 'CUPS 1.1'과 정확히 일치하는지 확인이 필요하고, 나머지 후보(22106, 22619, 24599, 1196)는 모두 DoS/크래시 위주라 코드수정 없는 원클릭 RCE로 보기 어렵다. 성공 시 잠재 영향(임의 코드실행)은 크지만 현재 자료만으로 자동화 실행 성공 가능성은 낮다.
- **port 3306 (mysql)** - confidence 0.05, risk `low` - 검색 결과는 전부 'mysql' 문자열이 이름에 들어간 PHP 웹앱의 XSS/SQLi/RFI 취약점이거나 cPanel/Asterisk 등 별도 소프트웨어의 로컬/모듈 취약점으로, 실제로 3306번 포트의 MySQL 서버 데몬 자체를 겨냥한 코드가 아니다. 최유력 후보(29653, Active Calendar XSS)도 별도의 PHP 웹앱 설치와 브라우저 상의 사용자 상호작용이 필요해 IP만 바꿔 대상 MySQL 서비스에 그대로 실행할 수 없다. 따라서 이 서비스에 코드수정 없이 통할 가능성은 사실상 없고, 그대로 자동 실행 시도는 즉시 실패(대상 없음/포트 불일치)할 것이다.
- **port 111 (rpcbind)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열이므로 rpcbind(RPC #100000)에 대해 매칭되는 공개 Exploit-DB PoC 자체가 없다. 실행할 코드가 없으므로 코드 수정 없이 바로 통할 가능성은 0이며, 별도의 오프셋/버전 수정 여부를 논할 대상도 존재하지 않는다. rpcbind는 보통 정보 노출(rpcinfo 열거)이나 다른 RPC 서비스(NFS, mountd 등) 공격의 사전 정찰용으로 활용되므로, 자동 실행 가능한 익스플로잇 관점에서의 위험도는 낮게 평가한다.


## Exploitation

### 192.168.56.104

- **[실패]** port 80 - Apache 2.0.52 - GET Denial of Service (방법: PoC 스크립트)
  - 스크립트는 연결과 페이로드 전송을 끝까지 완료했지만 마지막 메시지가 'maybe DoSeD'라는 불확실한 자체 추측일 뿐, 실제로 대상 웹서버가 다운되었거나 응답 불가 상태가 되었다는 검증된 증거(타임아웃, 연결 거부 등 후속 확인)가 로그에 없다.
- **[실패]** port 22 - OpenSSH 2.3 < 7.7 - Username Enumeration (PoC) (방법: PoC 스크립트)
  - 스크립트가 대상에 연결을 시도하기도 전에 Python 2/3 문법 오류(print 문)로 즉시 중단됨 - 대상과 무관한 로컬 실행 오류.
- **[실패]** port 22 - OpenSSH 2.3 < 7.7 - Username Enumeration (방법: Error code: 401 - {'type': 'error', 'error': {'type': 'authentication_error', 'message': 'API key is invalid.'}, 'request_id': None})
- **[실패]** port 22 - OpenSSH < 6.6 SFTP - Command Execution (방법: Error code: 401 - {'type': 'error', 'error': {'type': 'authentication_error', 'message': 'API key is invalid.'}, 'request_id': None})
- **[실패]** port 22 - OpenSSH < 7.7 - User Enumeration (2) (방법: Error code: 401 - {'type': 'error', 'error': {'type': 'authentication_error', 'message': 'API key is invalid.'}, 'request_id': None})
- **[실패]** port 443 - Apache 2.0.52 - GET Denial of Service (방법: PoC 스크립트)
  - 출력에 확정적 성공 신호(세션 획득, 서버 다운 확인 등)가 없고 스크립트 자체도 'maybe DoSed'라는 불확실한 문구로 끝나 실제 DoS 효과가 검증되지 않음.
- **[실패]** port 833 - rpcbind - CALLIT procedure UDP Crash (PoC) (방법: PoC 스크립트)
  - 출력이 완전히 비어 있어 세션 획득, 크래시 확인, 에러 메시지 등 성공/시도를 나타내는 어떤 신호도 없음 - 실행 자체가 아무 결과도 만들지 못한 것으로 보임.
- **[실패]** port 833 - RPCBind / libtirpc - Denial of Service (방법: failed to prepare job dir: timed out after 20s (guest session force-closed))
- **[실패]** port 631 - CUPS < 2.0.3 - Remote Command Execution (방법: PoC 복사 실패: timed out after 20s (guest session force-closed))
- **[실패]** port 3306 - Asterisk 'asterisk-addons' 1.2.7/1.4.3 - CDR_ADDON_MYSQL Module SQL Injection (방법: PoC 복사 실패: VBoxManage.exe: error: Error starting guest session (current status is: terminated)
)
- **[실패]** port 3306 - cPanel 10.8.x - cpwrap via MySQLAdmin Privilege Escalation (방법: PoC 복사 실패: VBoxManage.exe: error: Waiting for guest process failed: VERR_DUPLICATE
VBoxManage.exe: error: Details: code VBOX_E_IPRT_ERROR (0x80bb0005), component GuestSessionWrap, interface IGuestSession, callee IUnknown
VBoxManage.exe: error: Context: "WaitForArray(ComSafeArrayAsInParam(aSessionWaitFlags), 30 * 1000, &enmWaitResult)" at line 772 of file VBoxManageGuestCtrl.cpp
)
- **[성공]** port 80 - SQL Injection (uname) (방법: SQLi(sqlmap))
  - sqlmap이 확인한 인젝션: boolean-based blind
- **[성공]** port 443 - SQL Injection (uname) (방법: SQLi(sqlmap))
  - sqlmap이 확인한 인젝션: boolean-based blind

