# Pentest Report: 20260811-054231-e2e-verify-2026-08-11
## Summary

- 대상: 192.168.56.105
- 진행된 단계: exploitation, scanning, vuln_analysis
- 총 findings: 76


## Scanning

### 192.168.56.105
- 플랫폼 추정: `windows_standalone`

| Port | Service | Banner |
|---|---|---|
| 21 | ftp | vsftpd 2.3.4 |
| 22 | ssh | OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0) |
| 23 | telnet | Linux telnetd |
| 25 | smtp | Postfix smtpd |
| 53 | domain | ISC BIND 9.4.2 |
| 80 | http | Apache httpd 2.2.8 ((Ubuntu) DAV/2) |
| 111 | rpcbind | 2 (RPC #100000) |
| 139 | netbios-ssn | Samba smbd 3.X - 4.X (workgroup: WORKGROUP) |
| 445 | netbios-ssn | Samba smbd 3.X - 4.X (workgroup: WORKGROUP) |
| 512 | exec | netkit-rsh rexecd |
| 513 | login |  |
| 514 | shell | Netkit rshd |
| 1099 | java-rmi | GNU Classpath grmiregistry |
| 1524 | bindshell | Metasploitable root shell |
| 2049 | nfs | 2-4 (RPC #100003) |
| 2121 | ftp | ProFTPD 1.3.1 |
| 3306 | mysql | MySQL 5.0.51a-3ubuntu5 |
| 3632 | distccd | distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4)) |
| 5432 | postgresql | PostgreSQL DB 8.3.0 - 8.3.7 |
| 5900 | vnc | VNC (protocol 3.3) |
| 6000 | X11 | (access denied) |
| 6667 | irc | UnrealIRCd |
| 6697 | irc | UnrealIRCd |
| 8009 | ajp13 | Apache Jserv (Protocol v1.3) |
| 8180 | http | Apache Tomcat/Coyote JSP engine 1.1 |
| 8787 | drb | Ruby DRb RMI (Ruby 1.8; path /usr/lib/ruby/1.8/drb) |
| 38912 | nlockmgr | 1-4 (RPC #100021) |
| 47573 | mountd | 1-3 (RPC #100005) |
| 54226 | status | 1 (RPC #100024) |
| 57038 | java-rmi | GNU Classpath grmiregistry |
- `ftp_enum` 결과: {'anonymous_login_ok': True, 'listing': ''}
- `smb_enum` 결과: {'error': 'Kali 세션 락을 90s 넘게 못 얻음 - 다른 프로세스가 계속 점유 중이거나 stuck'}
- `http_enum` 결과: {'error': 'Kali 세션 락을 90s 넘게 못 얻음 - 다른 프로세스가 계속 점유 중이거나 stuck'}
- `ftp_enum` 결과: {'error': 'Kali 세션 락을 90s 넘게 못 얻음 - 다른 프로세스가 계속 점유 중이거나 stuck'}
- `http_enum` 결과: {'whatweb': '', 'gobuster': ''}


## Vulnerability Analysis

### 192.168.56.105

- **port 1524 (bindshell)** - confidence 0.05, risk `high` - searchsploit 검색 결과가 빈 배열([])로, 해당 서비스/버전에 매칭되는 공개 Exploit-DB PoC가 존재하지 않는다. 다만 Metasploitable 환경에서 포트 1524(ingreslock)는 이미 인증 없이 root 쉘을 제공하는 백도어로 알려져 있어, 별도 익스플로잇 코드 없이 단순히 nc로 접속하면 즉시 root 권한을 획득할 수 있다. 따라서 자동화된 익스플로잇 스크립트 실행이라는 관점에서는 confidence가 낮지만(적용 가능한 PoC 자체가 없으므로), 실제 침해 위험도는 매우 높다(risk: high).
- **port 25 (smtp)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열([])로, 배너에서 식별된 Postfix smtpd 서비스에 대응하는 공개 Exploit-DB 항목이 존재하지 않는다. 참조할 PoC 코드 자체가 없으므로 그대로 실행 가능 여부를 평가할 대상이 없으며, 별도의 취약점 스캐닝(버전 세부 확인, 설정 오류 점검 등)이나 수동 분석이 필요하다. 따라서 자동 실행형 익스플로잇으로서의 신뢰도는 0에 가깝고 현재 정보만으로는 위험도도 낮게 평가된다.
- **port 23 (telnet)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열([])로 반환되어 해당 배너(Linux telnetd)에 매칭되는 공개 Exploit-DB 항목이 존재하지 않는다. 참조할 PoC 코드 자체가 없으므로 코드 수정 여부를 판단할 대상이 없고, 자동 실행 가능성도 평가할 수 없다. 별도의 배너 그래빙(정확한 telnetd 버전/배포판 정보 확인)이나 수동 취약점 조사가 선행되어야 한다.
- **port 53 (domain)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열([])로 반환되어 ISC BIND 9.4.2에 대응하는 공개 Exploit-DB PoC 자체가 존재하지 않는다. 실제 코드가 없으므로 코드 수정 없이 바로 실행 가능한지 평가할 대상이 없으며, 자동 실행 성공 가능성은 0에 수렴한다. 위험도는 현재 확보된 공개 익스플로잇 기준으로는 낮으나, 이는 취약점 부재를 의미하지 않고 별도의 수동 취약점 조사(CVE 매칭, 배너 기반 알려진 BIND 9.4.x 취약점 확인 등)가 필요함을 나타낸다.
- **port 21 (ftp)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열([])로 반환되어 실제 PoC 코드나 메타데이터가 전혀 존재하지 않는다. vsftpd 2.3.4는 실제로 backdoor command execution 취약점(CVE-2011-2523)이 유명하지만, 제공된 DB 결과에 해당 항목이 없으므로 참조할 코드가 없어 자동 실행 가능성을 평가할 근거 자체가 없다. 따라서 confidence는 0에 가깝게 산정하며, 별도의 익스플로잇 코드를 확보하거나 직접 검증하지 않는 한 이 평가만으로는 실행 여부를 판단할 수 없다.
- **port 22 (ssh)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열([])로, OpenSSH 4.7p1 Debian 8ubuntu1 버전에 매칭되는 공개 Exploit-DB 항목이 존재하지 않는다. 참조할 PoC 코드 자체가 없으므로 코드 수정 여부를 판단할 대상도 없으며, 즉시 실행 가능한 기성 익스플로잇이 없다고 평가한다. 실제 취약점 존재 여부를 확인하려면 별도의 수동 분석(예: known CVE 목록 대조, 버전별 알려진 취약점 리서치)이 필요하다.
- **port 80 (http)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열([])로 반환되어 해당 배너(Apache httpd 2.2.8 (Ubuntu) DAV/2)에 매칭되는 공개 Exploit-DB 항목 자체가 존재하지 않는다. 평가할 PoC 코드가 없으므로 코드 수정 없이 바로 적용 가능한 익스플로잇이 없다고 판단하며, 자동 실행 성공 가능성은 0에 가깝다. 실제 취약점 평가를 위해서는 mod_dav, PHP, OpenSSL 등 부가 모듈/버전 정보를 추가로 확인해 다른 키워드로 재검색해야 한다.
- **port 111 (rpcbind)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열([])로 반환되어 rpcbind(포트 111, RPC #100000)에 대응하는 공개 Exploit-DB 항목 자체가 존재하지 않는다. 평가할 실제 PoC 코드가 없으므로 코드 수정 없이 그대로 통하는지 여부를 판단할 근거가 전혀 없으며, 자동 실행 가능성도 논할 수 없다. 이 배너/버전에 대해서는 별도의 수동 취약점 분석이나 다른 검색 키워드가 필요하다.
- **port 512 (exec)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열([])로, exec/rexecd(포트 512) 서비스에 대해 매칭되는 공개 Exploit-DB 항목이 존재하지 않는다. 참조할 PoC 코드 자체가 없으므로 코드 수정 여부를 논할 대상이 없고, 자동화된 그대로의 익스플로잇 실행은 불가능하다. 별도의 취약점 조사(수동 프로토콜 분석, 인증 우회 시도 등)나 다른 소스의 코드 확보가 선행되어야 한다.
- **port 139 (netbios-ssn)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열([])로 반환되어 해당 Samba smbd 3.X-4.X (workgroup: WORKGROUP) 배너에 매칭되는 공개 Exploit-DB 항목이 존재하지 않는다. 참조할 실제 PoC 코드가 없으므로 코드 수정 여부를 판단할 대상 자체가 없고, 그대로 실행 가능한 익스플로잇도 없다. 따라서 confidence는 0으로 평가하며, 즉시 사용 가능한 공개 익스플로잇이 없어 이 경로로 인한 즉각적 위험은 낮다.
- **port 445 (netbios-ssn)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열([])로 반환되어 해당 배너(Samba smbd 3.X-4.X, workgroup: WORKGROUP)에 매칭되는 공개 Exploit-DB 항목이 존재하지 않는다. 참조할 실제 PoC 코드가 전혀 없으므로 코드 수정 없이 그대로 통할지 여부 자체를 평가할 근거가 없으며, 자동 실행 가능한 익스플로잇이 없다고 판단된다. 따라서 confidence는 0에 가깝고, 즉시 악용 가능한 공개 코드가 없다는 점에서 risk는 low로 분류한다.
- **port 513 (login)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열로 반환되어 해당 서비스/포트(login, 513/rlogin 추정)에 매칭되는 공개 Exploit-DB 항목이 존재하지 않는다. 참조할 PoC 코드 자체가 없으므로 코드 수정 여부를 판단할 대상도 없고, 그대로 실행 가능한 익스플로잇이 없다고 평가한다. 따라서 자동 실행 성공 가능성은 0에 가까우며 이 항목으로 인한 위험도도 낮다.
- **port 514 (shell)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열([])로 반환되어 해당 서비스/버전(Netkit rshd, 포트 514)에 매칭되는 공개 Exploit-DB PoC가 존재하지 않는다. 참조할 실제 코드가 없으므로 코드 수정 없이 즉시 실행 가능한 익스플로잇 여부를 평가할 수 없으며, 자동 실행 성공 가능성은 사실상 0에 가깝다. 추가 익스플로잇을 찾으려면 다른 키워드(rsh, rlogin, rcmd 등)로 재검색하거나 수동 취약점 분석(예: .rhosts 신뢰 기반 인증 우회, IP 스푸핑 공격 등 rsh 프로토콜 자체의 설계 취약점)이 필요하다.
- **port 1099 (java-rmi)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열([])로 반환되어 java-rmi/GNU Classpath grmiregistry에 매칭되는 공개 Exploit-DB 항목이 존재하지 않는다. 참조할 PoC 코드 자체가 없으므로 코드 수정 없이 바로 실행 가능한지 여부를 평가할 대상이 없다. 따라서 이 경로로는 즉시 활용 가능한 공개 익스플로잇이 없다고 판단되며, 별도의 수동 RMI 취약점 분석(예: 등록된 객체 열거, 역직렬화 가젯 체인 확인 등)이 필요하다.
- **port 2049 (nfs)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열([])로 반환되어 해당 NFS(RPC #100003, v2-4) 서비스에 대응하는 공개 Exploit-DB 항목 자체가 존재하지 않는다. 참조할 PoC 코드가 없으므로 코드 수정 없이 그대로 실행 가능한지 여부를 평가할 대상이 없고, 자동 실행 성공 가능성도 판단할 근거가 없다. 따라서 confidence는 0에 가깝고, 즉시 활용 가능한 공개 익스플로잇이 없는 상태이므로 이 항목 자체의 위험도는 낮게 분류한다.
- **port 3306 (mysql)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열([])로 반환되어 MySQL 5.0.51a-3ubuntu5 버전에 매칭되는 공개 Exploit-DB 항목이 존재하지 않는다. 평가할 실제 PoC 코드 자체가 없으므로 코드 수정 필요 여부나 오프셋/버전 문자열 조정 여부를 판단할 근거도 없다. 따라서 이 서비스에 대해 즉시 활용 가능한 기존 공개 익스플로잇은 없다고 결론내리며, 신뢰도는 최하로 평가한다.
- **port 2121 (ftp)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열([])로 반환되어 ProFTPD 1.3.1에 매칭되는 공개 PoC/익스플로잇 코드 자체가 존재하지 않는다. 참조할 실제 코드가 없으므로 코드 수정 여부를 판단할 대상이 없으며, 자동 실행 가능성 평가도 불가능하다. 별도로 ProFTPD 1.3.1 관련 알려진 CVE(예: mod_copy, backdoor 등)를 대상으로 수동 조사 후 별도 DB 검색이나 exploit 소스 확보가 필요하다.
- **port 5432 (postgresql)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열([])로, PostgreSQL 8.3.0-8.3.7 버전에 대해 매칭되는 공개 Exploit-DB 항목이 존재하지 않는다. 참조할 PoC 코드 자체가 없으므로 코드 수정 없이 바로 실행 가능한지 여부를 판단할 근거가 전혀 없으며, 자동 실행 성공 가능성은 0에 가깝다. 이 배너/버전에 대해 즉시 활용 가능한 기존 익스플로잇이 없다고 결론내리는 것이 타당하다.
- **port 6000 (X11)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열이므로 해당 X11 서비스(포트 6000)에 대해 매칭되는 공개 Exploit-DB PoC가 존재하지 않는다. 참조할 실제 코드나 오프셋/버전 문자열이 전혀 없어 자동 실행은커녕 수정 기반 실행조차 판단할 근거가 없으므로 confidence는 0에 가깝고, 즉시 사용 가능한 익스플로잇이 없다는 점에서 현재 자동화 공격 위험도는 낮다고 평가한다.
- **port 6667 (irc)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열([])로 반환되어 참조할 수 있는 공개 PoC나 익스플로잇 코드가 전혀 없다. 배너 정보(UnrealIRCd)만으로는 정확한 버전을 알 수 없어 특정 취약점(예: 3.2.8.1 백도어)에 대응하는 항목을 매칭할 근거가 없으며, 코드가 없으므로 그대로 실행 가능 여부 자체를 평가할 수 없다. 따라서 confidence는 0에 가깝게 책정하며, 실행 가능한 익스플로잇이 없으므로 현재 시점의 risk도 low로 분류한다.
- **port 5900 (vnc)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열([])로, 해당 VNC 서비스(protocol 3.3)에 매칭되는 공개된 Exploit-DB 항목이 존재하지 않는다. 참조할 PoC 코드 자체가 없으므로 코드 수정 여부를 논할 대상이 없고, 자동 실행 가능한 기존 익스플로잇도 없다. 따라서 이 검색 결과만으로는 즉시 적용 가능한 공격 벡터가 없으며, 실제 취약점 평가를 위해서는 별도의 수동 분석(예: VNC 인증 우회, 약한 패스워드, RFB 프로토콜 취약점 등)이 필요하다.
- **port 8009 (ajp13)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열([])로, ajp13(포트 8009, Apache Jserv Protocol v1.3)에 해당하는 공개 Exploit-DB 항목이 존재하지 않는다. 참조할 실제 PoC 코드가 없으므로 코드 수정 없이 그대로 실행 가능한지 평가할 대상 자체가 없으며, 자동 실행 성공 가능성은 0에 가깝다. 이 서비스에 대한 익스플로잇을 시도하려면 별도의 취약점 조사나 커스텀 코드 작성이 필요하나, 이는 본 평가 범위를 벗어난다.
- **port 8180 (http)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열([])로 반환되어 해당 배너(Apache Tomcat/Coyote JSP engine 1.1, 포트 8180)에 대응하는 공개된 Exploit-DB PoC 자체가 존재하지 않는다. 참조할 코드가 없으므로 오프셋/버전 문자열 수정 여부를 논할 대상도 없으며, 자동 실행 가능성 자체를 평가할 수 없다. 실제 취약점 여부를 판단하려면 정확한 Tomcat 버전 확인 및 별도의 수동 점검(디폴트 계정, 알려진 CVE 대조 등)이 필요하다.
- **port 47573 (mountd)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열([])로 반환되어 mountd(RPC #100005, 포트 47573) 서비스/버전에 매칭되는 공개 Exploit-DB 항목이 존재하지 않는다. 참조할 PoC 코드 자체가 없으므로 코드 수정 여부를 평가할 대상도 없으며, 그대로 실행 가능한 익스플로잇이 전혀 없는 상태이다. 따라서 이 경로를 통한 자동화된 공격 성공 가능성은 현재 근거가 없어 confidence를 0으로, 즉시 악용 가능한 위험은 낮음으로 평가한다.
- **port 38912 (nlockmgr)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열([])로 반환되어 nlockmgr(RPC #100021, 포트 38912) 서비스에 대응하는 공개 Exploit-DB 항목이 존재하지 않는다. 참조할 PoC 코드 자체가 없으므로 코드 수정 없이 바로 실행 가능한지 여부를 판단할 근거가 전혀 없으며, 자동 실행 성공 가능성도 평가할 수 없다. 따라서 confidence는 0에 가깝게, risk는 즉시 활용 가능한 공개 익스플로잇이 없다는 점에서 낮게(low) 평가한다.
- **port 54226 (status)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열([])로 반환되어 해당 서비스(rpcbind/status, RPC #100024)에 매칭되는 공개 Exploit-DB 항목이 존재하지 않는다. 참조할 PoC 코드 자체가 없으므로 코드 수정 여부를 판단할 대상도 없고, 자동 실행 가능성 평가가 불가능하다. 따라서 confidence는 0에 가깝고, 즉시 활용 가능한 공개 익스플로잇이 없어 이 벡터로 인한 즉각적 위험도는 낮다.
- **port 6697 (irc)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열([])로 반환되어 해당 서비스/버전에 매칭되는 공개 Exploit-DB 항목이 존재하지 않는다. 참조할 PoC 코드 자체가 없으므로 코드 수정 없이 그대로 통할지 여부를 평가할 근거가 없으며, 자동 실행 성공 가능성도 판단할 수 없다. 배너 정보(UnrealIRCd, 포트 6697)만으로 추가 조사나 버전 특정 없이는 어떤 익스플로잇도 적용 대상이 될 수 없다.
- **port 57038 (java-rmi)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열([])로 반환되어 해당 서비스(java-rmi, GNU Classpath grmiregistry)에 대응하는 공개 Exploit-DB 항목이 존재하지 않는다. 참조할 PoC 코드 자체가 없으므로 코드 수정 여부를 판단할 대상도 없고, 그대로 실행 가능한 기존 익스플로잇이 전무하다. 따라서 자동 실행 성공 가능성은 0에 수렴하며, 이 상태에서는 위험도도 낮게 평가된다(별도의 커스텀 익스플로잇 개발이나 다른 벡터 탐색이 필요함).
- **port 3632 (distccd)** - confidence 0.00, risk `high` - searchsploit 검색 결과가 빈 배열([])로 반환되어 참조할 수 있는 기존 공개 PoC 코드나 메타데이터가 전혀 없다. distccd v1 자체는 CVE-2004-2687(--allow-all 옵션으로 인한 원격 명령 실행)이 널리 알려진 취약점이지만, 이는 별도의 공개 DB 항목이 아니라 distcc 프로토콜 자체의 설계 결함을 이용하는 방식(예: 자체 제작 익스플로잇 스크립트나 Metasploit 모듈)으로 익스플로잇해야 하므로, 여기 제공된 searchsploit 결과만으로는 코드 수정 없이 즉시 실행 가능한 항목이 없다고 평가한다. 실제 공격을 위해서는 대상 IP/포트 지정은 물론, distcc 프로토콜 메시지 포맷과 실행할 명령어(예: 리버스 쉘 페이로드)를 직접 구성해야 하므로 자동 실행 관점에서는 신뢰도가 매우 낮다.
- **port 8787 (drb)** - confidence 0.00, risk `high` - searchsploit 검색 결과가 빈 배열([])로 반환되어 Exploit-DB에 등록된 기존 PoC 코드가 존재하지 않는다. 따라서 코드 수정 없이 바로 실행 가능한 기존 익스플로잇 자체가 없으므로 자동 실행 성공 가능성은 0에 수렴한다. 다만 Ruby DRb는 프로토콜 특성상(임의 객체 메서드 호출 허용) 별도의 커스텀 익스플로잇(metasploit의 druby_remote_codeexec 등)을 사용하면 원격 코드 실행 위험이 매우 높은 서비스이므로, PoC 부재와 별개로 risk는 high로 평가한다.


## Exploitation

