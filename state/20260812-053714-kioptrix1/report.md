# Pentest Report: 20260812-053714-kioptrix1
## Summary

- 대상: 192.168.56.103
- 진행된 단계: exploitation, scanning, vuln_analysis
- 총 findings: 43


## Scanning

### 192.168.56.103
- 플랫폼 추정: `linux`

| Port | Service | Banner |
|---|---|---|
| 22 | ssh | OpenSSH 2.9p2 (protocol 1.99) |
| 80 | http | Apache httpd 1.3.20 ((Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b) |
| 111 | rpcbind | 2 (RPC #100000) |
| 139 | netbios-ssn | Samba smbd (workgroup: MYGROUP) |
| 443 | ssl/https | Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b |
| 32768 | status | 1 (RPC #100024) |
- `smb_enum` 결과: {'error': 'Kali 세션 락을 90s 넘게 못 얻음 - 다른 프로세스가 계속 점유 중이거나 stuck'}
- `http_enum` 결과: {'whatweb': '', 'gobuster': '.hta                 (Status: 403) [Size: 268]\n.htaccess            (Status: 403) [Size: 273]\n.htpasswd            (Status: 403) [Size: 273]\n~operator            (Status: 403) [Size: 273]\n~root                (Status: 403) [Size: 269]\ncgi-bin/             (Status: 4...


## Vulnerability Analysis

### 192.168.56.103

- **port 22 (ssh)** - confidence 0.15, risk `low` - 45210.py의 제목은 'OpenSSH 2.3 < 7.7'로 넓게 잡혀 있지만 실제 CVE-2018-15473 취약점은 auth2-gss.c/auth2-hostbased.c/auth2-pubkey.c의 privsep monitor 관련 리팩터링 이후 코드에 존재하며, 이는 2.9p2(2001년, protocol 1.99, 아직 SSH1/2 과도기 코드베이스)보다 한참 후에 도입된 구조라 해당 코드 경로 자체가 없을 가능성이 높다 - 즉 searchsploit의 버전 범위 매칭이 부정확한 오탐일 가능성이 크다. 설령 서비스가 응답하더라도 이 CVE는 단순 사용자명 존재 여부 열거(CVSS 5.3, MEDIUM)일 뿐이라 위험도는 낮고, 나머지 후보(45000/45001 SFTP 커맨드 실행, 40962/40963 로컬·에이전트 포워딩)는 각각 특정 변형 SFTP 서버나 로컬 접근/포워딩 전제 조건이 필요해 이 배너만으로는 그대로 적용하기 어렵다.
- **port 111 (rpcbind)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열([])로, rpcbind(포트 111, RPC #100000)에 대해 매칭되는 공개 Exploit-DB 항목이 전혀 존재하지 않는다. 평가할 PoC 코드 자체가 없으므로 대상 IP만 바꿔 그대로 실행 가능한 기성 익스플로잇은 없다고 판단되며, 자동 실행 성공 가능성은 0에 가깝다. rpcbind는 그 자체로는 원격 코드실행 취약점보다는 포트매핑/정보노출(rpcinfo enum) 및 이를 이용한 후속 서비스(NFS, NIS 등) 공격의 진입점 역할을 하는 경우가 많으므로, 필요하다면 rpcbind가 노출하는 개별 RPC 프로그램(nfs, mountd, ypbind 등) 기준으로 별도 검색을 재시도하는 것이 적절하다.
- **port 443 (ssl/https)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열이라 Exploit-DB에 등록된 기존 PoC가 없으며, 참조할 실제 코드가 전무하므로 코드 수정 없이 그대로 실행 가능한 익스플로잇이 존재한다고 판단할 근거가 없다. Apache 1.3.20/mod_ssl 2.8.4/OpenSSL 0.9.6b 조합은 역사적으로 취약점(예: mod_ssl 원격 버퍼오버플로우류)이 있었지만 해당 DB 검색에서 매칭되는 항목이 없으므로 자동 실행 파이프라인 기준으로는 즉시 활용 가능한 공개 익스플로잇 없음으로 분류한다.
- **port 139 (netbios-ssn)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열이라 이 Samba smbd(workgroup MYGROUP) 배너에 매칭되는 공개 PoC 자체가 존재하지 않는다. 참조할 실제 코드가 없으므로 '수정 없이 그대로 통할지'를 판단할 대상이 없고, 자동 실행 성공 가능성은 사실상 0으로 평가한다. 버전 문자열(빌드/패치 레벨)이 특정되지 않아 향후 검색 시에도 정확한 CVE/EDB 항목을 찾으려면 smbclient/enum4linux 등으로 정확한 Samba 버전을 먼저 확인하는 추가 정보 수집이 필요하다.
- **port 80 (http)** - confidence 0.00, risk `low` - searchsploit 결과가 빈 배열이라 참조할 수 있는 공개 PoC 코드 자체가 없다. 따라서 코드 수정 없이 그대로 실행 가능한 익스플로잇이 존재하는지 판단할 근거가 없으며, 자동 실행 성공 가능성은 사실상 0이다. (참고로 mod_ssl 2.8.4/OpenSSL 0.9.6b 조합은 역사적으로 CVE-2002-0082(Slapper) 등 취약점이 알려져 있으나, 이는 별도의 exploit-db 검색·PoC 확보가 선행되어야 평가 가능하다.)
- **port 32768 (status)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열이라 rpc.statd(RPC #100024) 관련 공개 PoC가 데이터베이스에 존재하지 않는다. 실행 가능한 익스플로잇 코드 자체가 없으므로 자동 실행 성공 가능성은 0에 가깝다. 배너 정보만으로는 취약 여부를 판단할 근거가 없어 별도 버전 확인이나 수동 조사가 필요하다.


## Exploitation

### 192.168.56.103

- **[실패]** port 22 - OpenSSH 2.3 < 7.7 - Username Enumeration (PoC) (방법: PoC 스크립트)
  - 실행이 대상 서버와의 통신 이전, 로컬 파이썬 파싱 단계에서 SyntaxError로 즉시 중단됨 (Python 2 print문을 Python 3로 실행). 취약점 자체와는 무관한 환경/스크립트 문제이며 세션 획득이나 응답 시간차 등 성공 신호가 전혀 없음.
- **[실패]** port 22 - OpenSSH 2.3 < 7.7 - Username Enumeration (방법: PoC 스크립트)
  - 출력은 Metasploit 세션 성공 신호나 실제 코드 실행 증거 없이, 로컬 파이썬 스크립트의 TabError(tabs/spaces 혼용 들여쓰기)로 인한 구문 오류로 즉시 종료된 것이다. 대상과의 통신 자체가 이루어지지 않은 순수 스크립트 결함이다.
- **[실패]** port 22 - OpenSSH < 6.6 SFTP - Command Execution (방법: PoC 스크립트)
  - 스크립트가 Python 2 문법(print 문)을 Python 3으로 실행해 37번째 줄에서 SyntaxError로 즉시 종료됨 - 대상에 대한 네트워크 연결이나 익스플로잇 시도 자체가 이루어지지 않았음.
- **[실패]** port 22 - OpenSSH < 7.7 - User Enumeration (2) (방법: PoC 스크립트)
  - 스크립트가 대상에 연결하기 전에 로컬에서 Python 2 문법(print 문)을 Python 3 인터프리터로 실행해 SyntaxError로 종료됨. 실제 익스플로잇 로직은 실행조차 되지 않음.
- **[실패]** port 80 - SQL Injection (sqlmap --forms) (방법: SQLi(sqlmap))

