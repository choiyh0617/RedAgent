# Pentest Report: 20260812-024639-e2e-verify-clean2-2026-08-11
## Summary

- 대상: 192.168.56.105
- 진행된 단계: exploitation, scanning, vuln_analysis
- 총 findings: 142


## Scanning

### 192.168.56.105
- 플랫폼 추정: `linux`

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
| 46499 | nlockmgr | 1-4 (RPC #100021) |
| 46569 | java-rmi | GNU Classpath grmiregistry |
| 46671 | mountd | 1-3 (RPC #100005) |
| 47486 | status | 1 (RPC #100024) |
- `ftp_enum` 결과: {'anonymous_login_ok': True, 'listing': ''}
- `http_enum` 결과: {'error': 'Kali 세션 락을 90s 넘게 못 얻음 - 다른 프로세스가 계속 점유 중이거나 stuck'}
- `http_enum` 결과: {'error': 'Kali 세션 락을 90s 넘게 못 얻음 - 다른 프로세스가 계속 점유 중이거나 stuck'}
- `ftp_enum` 결과: {'error': 'Kali 세션 락을 90s 넘게 못 얻음 - 다른 프로세스가 계속 점유 중이거나 stuck'}
- `smb_enum` 결과: {'enum4linux': ''}


## Vulnerability Analysis

### 192.168.56.105

- **port 21 (ftp)** - confidence 0.95, risk `high` - vsftpd 2.3.4의 백도어는 배포 아카이브에 삽입된 고정 트리거(USER 필드에 ':)' 포함 시 포트 6200에서 루트 셸 바인드)로, 오프셋 계산이나 버전별 리턴주소 조정이 필요한 메모리 손상형 익스플로잇이 아니라 단순 프로토콜 트리거이므로 대상 IP만 지정해도 코드 수정 없이 그대로 동작할 가능성이 매우 높다. 배너가 정확히 'vsftpd 2.3.4'로 확인되었고 CVE-2011-2523(CVSS 9.8, 인증 불필요, 루트 권한 셸)과 정확히 일치해 위험도는 high로 평가된다. 다만 앤티멀웨어/트래픽검사 도구나 백도어 코드가 제거된 재빌드 버전(사설 미러 등)에서는 6200 포트가 열리지 않을 수 있어 100% 확신은 아니다.
- **port 23 (telnet)** - confidence 0.60, risk `high` - PoC는 메모리 손상이 아니라 NEW-ENVIRON USER='-f root' 프로토콜 로직 결함을 이용하므로 오프셋/포트 하드코딩 같은 이진 수정 없이 대상 IP만으로 실행 가능한 구조다. 다만 배너가 단순히 'Linux telnetd'라 GNU Inetutils 2.0~2.6인지 netkit-telnet/BSD 계열(다른 두 후보)인지 사전 확인이 필요하고, telnetd가 실제로 USER 값을 검증 없이 /bin/login에 전달하며 login이 -f 플래그를 허용하는 설정인지에 따라 성공 여부가 갈린다. 성공 시 인증 없이 즉시 root 셸을 얻는 CVSS 9.8급 취약점이라 위험도는 high로 평가한다.
- **port 6667 (irc)** - confidence 0.55, risk `high` - 16922.rb는 오프셋이나 버전 문자열 조정이 필요 없는 단순 TCP 접속 후 'AB;<command>\n' 전송 방식이라, 실제로 트로이목마화된 UnrealIRCd 3.2.8.1 바이너리라면 RHOST/RPORT만 지정해도 코드 수정 없이 그대로 동작한다(CVE-2010-2075, CVSS 7.5, 임의 명령 실행). 다만 주어진 배너에는 버전 번호가 없어 정확히 3.2.8.1인지, 그리고 2009년 11월~2010년 6월 사이 배포된 변조 tar.gz로 빌드된 것인지(백도어는 특정 배포본에만 존재) 확인이 안 되므로 완전한 확신은 어렵다 - 실패 시엔 코드가 아니라 대상 자체에 백도어가 없는 것이며 수정으로 해결될 문제가 아니다. 나머지 후보(13853은 동일 백도어의 Perl판이라 같은 전제조건, 18011은 Windows 로컬 DoS라 원격 IRC 서비스에 부적용, 27407은 3.2.3 대상의 2006년 구식 DoS라 3.2.8.1에 미해당)는 이 타겟에 적합하지 않다.
- **port 6697 (irc)** - confidence 0.30, risk `high` - 16922.rb only works if this is literally the trojaned Unreal3.2.8.1.tar.gz build (backdoor present Nov 2009–Jun 2010) rather than a clean 3.2.8.1 or any other version — the banner alone doesn't confirm this, so version/build must be verified first (e.g. by probing the 'AB;id' backdoor harmlessly) before trusting auto-exploit. It also needs RPORT changed from the module default 6667 to 6697, and since 6697 is the conventional IRC-over-TLS port, the SSL datastore option likely needs enabling too, so it isn't a pure 'just pass the IP' run. If the backdoor is confirmed present, impact is unauthenticated arbitrary command execution (CVE-2010-2075, CVSS 7.5), hence high risk despite the moderate confidence; the other three DB entries (18011, 13853, 27407) are DoS/older-CVE/legacy downloader variants and are lower priority or Windows/PoC-format mismatches, not directly relevant here.
- **port 2049 (nfs)** - confidence 0.05, risk `low` - searchsploit 검색 결과가 빈 배열([])로, NFS(RPC #100003)에 대해 매칭되는 공개 Exploit-DB 항목이 전혀 없다. 실행 가능한 PoC 코드 자체가 존재하지 않으므로 코드 수정 여부를 논할 대상이 없고, 자동 실행으로 통할 기존 익스플로잇이 없다고 판단된다. NFS 자체는 mount 권한/exports 설정 오류(no_root_squash 등) 기반의 설정 취약점이 흔하지만 이는 별도의 수동 점검이 필요하며 이번 검색 결과에는 해당되지 않는다.
- **port 513 (login)** - confidence 0.02, risk `low` - 포트 513은 rlogin(원격 셸) 프로토콜이며 HTTP 기반 서비스가 아닌데, 검색 결과는 전부 'login.php'/'login.asp' 등 웹 애플리케이션의 SQL Injection·XSS·RFI 취약점으로 단순 키워드('login') 매칭에 의한 오탐이다. PoC(34111)도 웹 폼 파라미터에 SQLi 페이로드를 넣는 방식이라 rlogin 프로토콜 자체와는 전송 계층·인증 방식이 전혀 달라 대상 IP만 바꿔서는 절대 통하지 않으며, 근본적으로 프로토콜이 맞지 않아 오프셋/포트 수정 수준이 아니라 완전히 다른 익스플로잇(rlogin 관련 CVE, 예: .rhosts 신뢰 인증 우회 등)을 찾아야 한다.
- **port 25 (smtp)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열([])로, 이 서비스(Postfix smtpd, 포트 25)에 해당하는 공개 Exploit-DB 항목이 전혀 존재하지 않는다. 참조할 PoC 코드 자체가 없으므로 코드 수정 없이 실행 가능한지 여부를 평가할 대상이 없고, 자동 실행 성공 가능성은 0에 가깝다. 배너만으로는 구체적 CVE/버전 취약점을 특정할 수 없어 별도의 수동 조사(버전별 CVE 검색 등)가 필요하다.
- **port 53 (domain)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열이라 평가할 실제 PoC 코드나 메타데이터가 존재하지 않는다. 즉 코드 수정 없이 바로 실행 가능한 공개 익스플로잇이 DB상 확인되지 않으므로 confidence는 0에 가깝다. BIND 9.4.2는 오래된 버전으로 알려진 CVE들이 있을 수 있으나, 이 결과만으로는 자동 실행 가능한 항목을 특정할 수 없어 자동화 관점의 risk는 낮게 평가한다.
- **port 22 (ssh)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열이라 이 OpenSSH 4.7p1 Debian 8ubuntu1 버전에 대응하는 공개 Exploit-DB PoC 자체가 존재하지 않는다. 평가할 실제 코드가 없으므로 코드수정 없이 그대로 통할 익스플로잇이 있다고 판단할 근거가 전혀 없어 confidence는 0에 가깝다. 자동 실행 가능한 기성 익스플로잇이 없다는 의미에서 즉각적인 risk는 low로 분류하되, 이는 취약점이 없다는 뜻이 아니라 별도의 수동 조사(예: 배너에 특정된 CVE 매칭)가 필요하다는 의미다.
- **port 111 (rpcbind)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열([])로, rpcbind(포트 111, RPC #100000)에 대해 매칭되는 공개 Exploit-DB 항목이 존재하지 않는다. 참조할 PoC 코드 자체가 없으므로 코드 수정 없이 그대로 통할지 여부를 평가할 대상이 없고, 자동 실행 가능한 기성 익스플로잇도 없다. rpcbind 자체는 통상 정보 노출(rpcinfo 스캔)이나 이후 단계(NFS/NIS 등 개별 RPC 서비스) 공격의 진입점 역할을 하므로, 낮은 confidence와 함께 낮은 즉시 위험도로 분류한다.
- **port 80 (http)** - confidence 0.00, risk `low` - searchsploit이 이 배너(Apache 2.2.8 Ubuntu, mod_dav)에 대해 반환한 항목이 전혀 없어(빈 배열) 평가할 실제 PoC 코드 자체가 존재하지 않는다. 코드 수정 여부를 판단할 대상이 없으므로 '그대로 통할' 가능성은 0에 가깝고, 이 결과만으로는 자동 실행 가능한 익스플로잇이 없다고 봐야 한다. Apache 2.2.8/mod_dav 자체는 알려진 CVE(예: Range header DoS 등)가 있을 수 있으나 ExploitDB에 매칭되는 항목이 없으므로 별도로 CVE/벤더 권고안을 직접 조사해야 한다.
- **port 139 (netbios-ssn)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열([])로, 배너 문자열(Samba smbd 3.X-4.X)에 매칭되는 공개 PoC/Exploit-DB 항목이 전혀 존재하지 않는다. 참조할 실제 코드가 없으므로 코드 수정 없이 그대로 실행 가능한 익스플로잇도 없고, 자동 실행 시도 자체가 성립하지 않는다. 버전 범위가 매우 넓어(3.X-4.X) 특정 CVE(subtype/버전) 식별을 위해서는 별도의 버전 핑거프린팅(smbclient, enum4linux, msf auxiliary/scanner 등)이 선행되어야 한다.
- **port 445 (netbios-ssn)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열([])로, 이 배너(Samba smbd 3.X-4.X, workgroup: WORKGROUP)에 매칭되는 공개 Exploit-DB PoC 자체가 존재하지 않는다. 배너 문자열만으로는 정확한 마이너 버전을 특정할 수 없어 코드 수정 없이 바로 통할 기존 익스플로잇을 판단할 근거가 전혀 없으므로 confidence는 최저로 둔다. 실제 위험도를 평가하려면 smbclient/enum4linux 등으로 정확한 버전을 먼저 확인하고 해당 버전에 맞는 CVE(EternalRed/CVE-2017-7494 등)를 별도로 검색해야 한다.
- **port 512 (exec)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열([])로, netkit-rsh rexecd(포트 512)에 대응하는 공개 Exploit-DB 항목이 존재하지 않는다. 참조할 실제 PoC 코드 자체가 없으므로 코드 수정 없이든 수정을 거치든 자동 실행할 익스플로잇이 없어 confidence는 0에 가깝다. rexecd 자체는 평문 자격증명 기반 원격 실행 서비스로 잠재적 위험은 있으나, 이는 알려진 취약점이 아닌 서비스 설계 특성이므로 risk는 낮게 평가한다.
- **port 1099 (java-rmi)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열([])로, 해당 java-rmi/GNU Classpath grmiregistry 서비스에 매칭되는 공개 Exploit-DB 항목이 전혀 존재하지 않는다. 참조할 PoC 코드 자체가 없으므로 코드 수정 여부를 판단할 대상도 없고, 대상 IP만 넣어 그대로 실행 가능한 기성 익스플로잇은 없다고 결론짓는다. 이 서비스에 대한 자동화된 원클릭 공격은 불가능하며, 필요하다면 수동으로 RMI 레지스트리 열거(rmiregistry 바인딩 확인) 및 커스텀 역직렬화/코덱베이스 공격 벡터를 별도로 조사해야 한다.
- **port 514 (shell)** - confidence 0.00, risk `low` - searchsploit 결과가 빈 배열이라 Netkit rshd(port 514) 대상으로 활용 가능한 공개 PoC/모듈이 Exploit-DB에 존재하지 않는다. 코드 수정 없이 바로 실행 가능한 기존 익스플로잇 자체가 없으므로 자동 실행 성공 가능성과 confidence는 0에 가깝다. rsh 프로토콜 자체는 평문 통신과 .rhosts 기반 신뢰 인증이라는 구조적 약점이 있어 별도의 수동 진단(서비스 설정 오류, 신뢰 관계 오용 등)으로 접근할 여지는 있으나, 이는 기존 공개 익스플로잇 재사용과는 무관하므로 본 항목의 risk는 low로 평가한다.
- **port 2121 (ftp)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열([])로 반환되어 해당 버전(ProFTPD 1.3.1)에 매칭되는 공개 PoC 코드 자체가 없다. 코드가 없으므로 오프셋/포트 수정 여부를 논할 대상도 없고, 자동 실행 파이프라인에서 그대로 통할 익스플로잇이 존재하지 않는다.
- **port 3306 (mysql)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열([])로, MySQL 5.0.51a-3ubuntu5에 대해 매칭되는 공개 Exploit-DB 항목이 전혀 없다. 평가할 PoC 코드 자체가 존재하지 않으므로 코드 수정 없이 즉시 통할 익스플로잇이 없다고 판단하며, 이 배너 버전 대상 원격 공격은 별도 취약점 조사(예: 약한 자격증명, UDF 권한상승 등 비-Exploit-DB 경로)가 필요하다.
- **port 5900 (vnc)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열이므로 이 VNC(protocol 3.3) 배너에 대응하는 공개 PoC 자체가 존재하지 않는다. 평가할 실제 코드가 없으므로 코드 수정 없이 바로 통할 익스플로잇이 있다고 판단할 근거가 전혀 없다. 자동 실행 성공 가능성은 사실상 0이며, 이 서비스에 대해서는 별도 취약점 스캔이나 수동 분석이 필요하다.
- **port 6000 (X11)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열([])로, 이 서비스에 대해 공개된 Exploit-DB 항목이 전혀 존재하지 않는다. 참조할 PoC 코드 자체가 없으므로 코드 수정 없이 그대로 실행 가능한 익스플로잇도 없고, 오프셋/포트/버전 문자열을 고쳐서 쓸 대상조차 없다. 배너도 'access denied'만 노출되어 버전 식별이 불가능한 상태라 confidence는 0에 가깝게, 즉시 위협은 낮음으로 평가한다.
- **port 5432 (postgresql)** - confidence 0.00, risk `low` - searchsploit 결과가 빈 배열([])로, PostgreSQL 8.3.0-8.3.7 배너에 매칭되는 공개 PoC/익스플로잇 항목이 DB에 존재하지 않는다. 평가할 실제 코드가 없으므로 코드수정 없이 바로 통할 익스플로잇이 없다는 뜻이며, 자동 실행 가능한 기성 익스플로잇 자체가 부재하다. 이 상태에서는 confidence를 0에 가깝게, risk는 '즉시 활용 가능한 기성 공격 수단 없음' 기준으로 low로 판단한다(단, 다른 버전/CVE 기반 검색어로 재검색하거나 별도 취약점 스캔이 필요할 수 있음).
- **port 8180 (http)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열([])로, 이 배너(Apache Tomcat/Coyote JSP engine 1.1)에 매칭되는 공개 Exploit-DB 항목이 전혀 없다. 평가할 PoC 코드 자체가 존재하지 않으므로 코드 수정 없이 즉시 통할 기성 익스플로잇은 없다고 판단되며, confidence는 0에 가깝게, 자동 실행 가능한 기성 공격 수단이 없다는 의미에서 risk는 low로 분류한다.
- **port 46499 (nlockmgr)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열이므로 nlockmgr(RPC #100021, 포트 46499) 대상의 공개 Exploit-DB PoC 자체가 존재하지 않는다. 참조할 실제 코드가 없어 오프셋/포트/버전 문자열 수정 여부를 논할 대상도 없으며, 무수정 자동 실행이 가능한 기존 익스플로잇이 없으므로 confidence는 0에 가깝고 이 항목으로 인한 위험은 없다.
- **port 46569 (java-rmi)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열이므로 이 java-rmi(GNU Classpath grmiregistry, 포트 46569) 서비스/버전에 대응하는 공개 Exploit-DB PoC가 존재하지 않는다. 참조할 실제 코드가 없어 대상 IP만 넣어 그대로 실행 가능한지 여부 자체를 평가할 수 없으므로 confidence는 0으로 처리한다. 자동 실행 가능한 기존 익스플로잇이 없어 이 경로로 인한 즉각적 위험은 낮으며, 필요하다면 별도의 수동 분석(RMI 등록소 codebase 로딩, JEP 290 이전 역직렬화 취약점 등)이 요구된다.
- **port 46671 (mountd)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열이라 mountd(RPC #100005, 포트 46671)에 대응하는 공개 Exploit-DB 항목이 존재하지 않는다. 참조할 PoC 코드 자체가 없으므로 코드 수정 없이 그대로 실행 가능한지 판단할 대상이 없고, 자동 실행 성공 가능성도 0에 가깝다. 이 서비스에 대한 익스플로잇은 수동 취약점 분석이나 다른 소스를 통해 별도로 확보해야 한다.
- **port 47486 (status)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열([])로, 이 서비스/버전에 대해 공개된 Exploit-DB 항목이 전혀 존재하지 않는다. 참조할 PoC 코드 자체가 없으므로 코드 수정 없이 그대로 실행 가능한 익스플로잇은 없으며, 이 상태에서는 자동 실행 성공 가능성을 평가할 근거도 없다. 추가 익스플로잇을 찾으려면 다른 검색어(예: rpc.statd, portmapper 100024)로 재검색하거나 수동 취약점 분석이 필요하다.
- **port 8009 (ajp13)** - confidence 0.00, risk `medium` - searchsploit 결과가 빈 배열이라 참고할 공개 PoC 코드 자체가 없으므로 '코드 수정 없이 그대로 통할 가능성'을 평가할 대상이 존재하지 않는다(confidence 0). AJP13/mod_jk 프로토콜은 구조적으로 파일 읽기·요청 스머글링류 취약점(예: Ghostcat 계열) 사례가 알려져 있어 노출 자체의 위험도는 medium으로 보되, 이번 검색 결과만으로는 버전 특정 취약점 유무나 익스플로잇 성공 여부를 판단할 근거가 없다. 자동 실행을 시도하려면 별도로 CVE/버전 매칭 및 PoC 확보·오프셋·타깃 경로 커스터마이징이 필요하다.
- **port 8787 (drb)** - confidence 0.00, risk `medium` - 제공된 searchsploit 결과가 빈 배열이므로 이 서비스에 매칭되는 공개 Exploit-DB PoC가 존재하지 않아 코드 수정 없이 즉시 실행 가능한 익스플로잇이 없다. Ruby DRb 자체는 인증/ACL 미설정 시 임의 객체 메서드 호출을 통한 RCE 위험이 구조적으로 존재하는 서비스(별도 도구인 Metasploit drb_remote_codeexec 등으로 알려짐)라 위험도는 medium~high로 볼 수 있으나, 이는 searchsploit 검색 대상 밖의 지식이라 이번 평가(“기존 DB 결과가 그대로 통하는지”)에는 반영하지 않았다. 결론적으로 이 검색 결과 기준으로는 재사용 가능한 항목이 없어 confidence 0으로 판단한다.
- **port 1524 (bindshell)** - confidence 0.00, risk `high` - searchsploit 검색 결과가 빈 배열이라 참조할 공개 PoC 코드 자체가 없으므로 '기존 코드 그대로 실행' 관점의 confidence는 0이다. 다만 포트 1524는 Metasploitable의 잘 알려진 ingreslock 백도어로, 별도 익스플로잇 코드 없이 단순 TCP 연결(nc <IP> 1524)만으로 root 쉘을 획득할 수 있는 구조라 서비스 자체의 위험도는 매우 높다. searchsploit 항목이 없으므로 이 파이프라인에서는 '적용 가능한 기존 DB 익스플로잇 없음'으로 분류하고, 필요시 별도의 raw 소켓 연결 방식(비-Exploit-DB 기법)으로 검증해야 한다는 점을 rationale로 남긴다.
- **port 3632 (distccd)** - confidence 0.00, risk `high` - searchsploit 검색 결과가 빈 배열([])로, 참조할 수 있는 공개 PoC 코드 자체가 없어 '코드 수정 없이 그대로 실행 가능한 익스플로잇'으로 평가할 대상이 존재하지 않는다. distccd v1(GNU 4.2.4)은 CVE-2004-2687(--allow-all 설정 시 인증 없는 원격 명령 실행)로 잘 알려진 서비스라 서비스 자체의 위험도는 high이지만, 이는 이번 검색 결과와 무관한 배경지식이며 판단 근거로 삼을 실제 PoC가 없으므로 confidence는 0으로 매긴다. 만약 실제 공격을 진행하려면 별도로 distcc 프로토콜(DIST00000...ARGC/ARGV 형식)을 구현한 스크립트나 Metasploit의 exploit/unix/misc/distcc_exec 모듈을 사용해야 하며, 이는 이번 searchsploit 결과의 범위를 벗어난다.


## Exploitation

### 192.168.56.105

- **[실패]** port 21 - vsftpd 2.3.4 - Backdoor Command Execution (Metasploit) (방법: PoC 스크립트)
  - 출력에는 'stdbuf: failed to run command cd'라는 로컬 실행 오류만 있을 뿐, 세션 획득이나 명령 실행 성공을 나타내는 신호(예: 'Command shell session N opened', 셸 프롬프트, 명령 결과)가 전혀 없다. PoC 스크립트 자체가 타겟에 도달하기 전에 로컬에서 실패한 것으로 보인다.
- **[실패]** port 21 - vsftpd 2.3.4 - Backdoor Command Execution (방법: PoC 스크립트)
  - 출력은 PoC 스크립트 자체가 'cd'를 외부 명령으로 실행하려다 실패한 stdbuf 오류일 뿐이며, 백도어 쉘 연결이나 명령 실행 결과, 세션 획득의 증거가 전혀 없다. 스크립트 실행 단계에서 실패한 것으로 취약점 트리거 여부조차 확인되지 않는다.
- **[실패]** port 23 - GNU InetUtils 2.6 - Telnetd Remote Privilege Escalation (방법: Metasploit(exploit/linux/telnet/gnu_inetutils_auth_bypass))
  - 출력에 'Exploit completed, but no session was created'와 'No active sessions'가 명시되어 있고, 텔넷 연결 시도 로그 이후 실제 명령 실행이나 세션 생성 흔적이 전혀 없어 익스플로잇이 실패했음을 나타낸다.
- **[실패]** port 23 - netkit-telnet-0.17 telnetd (Fedora 31) - 'BraveStarr' Remote Code Execution (방법: PoC 스크립트)
  - 출력은 'cd' 명령을 실행하지 못했다는 stdbuf 오류 메시지뿐이며, 셸 세션 획득이나 코드 실행 성공을 나타내는 어떠한 신호도 없다.
- **[실패]** port 23 - TelnetD encrypt_keyid - Function Pointer Overwrite (방법: Metasploit(exploit/freebsd/telnet/telnet_encrypt_keyid))
  - 출력에 'Exploit aborted due to failure: unknown: This system does not support encryption'라는 명시적 실패 메시지가 있고, 세션 목록도 'No active sessions'로 활성 세션이 전혀 없어 코드 실행이나 쉘 접근이 이루어지지 않았다.
- **[실패]** port 6667 - UnrealIRCd 3.2.8.1 - Backdoor Command Execution (Metasploit) (방법: Metasploit(exploit/unix/irc/unreal_ircd_3281_backdoor))
  - 출력에 "Exploit completed, but no session was created."와 "No active sessions."가 명시되어 있어 세션 획득에 실패했음을 나타내며, IRC 사용자 등록 시도 이후 별다른 쉘/세션 신호가 없다.
- **[실패]** port 6667 - UnrealIRCd 3.2.8.1 - Remote Downloader/Execute (방법: Metasploit(exploit/unix/irc/unreal_ircd_3281_backdoor))
  - 출력에 'Exploit completed, but no session was created'와 'No active sessions'가 명시되어 있어 세션 획득이나 코드 실행에 실패했음을 보여준다. 리버스 쉘 핸들러는 시작됐지만 콜백이 없었다.
- **[실패]** port 6667 - UnrealIRCd 3.x - Remote Denial of Service (방법: PoC 스크립트)
  - 출력은 대상 서버와의 통신 결과가 아니라 로컬 실행 환경 오류(stdbuf가 'cd' 명령을 실행하지 못함)이며, PoC 스크립트 자체가 대상에 도달하지도 못한 것으로 보인다. DoS 발생이나 서비스 다운을 나타내는 신호가 전혀 없다.
- **[실패]** port 6697 - UnrealIRCd 3.2.8.1 - Backdoor Command Execution (Metasploit) (방법: Metasploit(exploit/unix/irc/unreal_ircd_3281_backdoor))
  - 출력에 'Exploit completed, but no session was created.'와 'No active sessions.'가 명시되어 있고, IRC 사용자 등록 시도 이후 백도어 트리거나 페이로드 실행 성공을 나타내는 어떤 메시지도 없어 세션 획득에 실패했다.
- **[실패]** port 6697 - UnrealIRCd 3.2.8.1 - Remote Downloader/Execute (방법: 응답에 텍스트 블록이 없음 (stop_reason=refusal))
- **[실패]** port 6697 - UnrealIRCd 3.x - Remote Denial of Service (방법: PoC 스크립트)
  - 출력은 PoC 스크립트 실행 환경의 오류(stdbuf가 셸 내장 명령 'cd'를 실행 파일로 찾지 못함)일 뿐, 대상 192.168.56.105:6697에 대한 어떠한 연결 시도나 DoS 효과도 나타내지 않는다.
- **[실패]** port 513 - Airties - login-cgi Buffer Overflow (Metasploit) (방법: Metasploit(exploit/linux/http/airties_login_cgi_bof))
  - 출력에 'Exploit completed, but no session was created'와 'Connection reset by peer' 에러가 명시되어 있고, 세션 목록도 'No active sessions'로 비어 있어 코드 실행이나 쉘 획득에 실패했음을 보여준다.

